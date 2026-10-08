#!/usr/bin/env elixir
# encscan.exs — listet Dateien rekursiv mit Typ und erkanntem Encoding auf
# und hebt Abweichler pro Dateityp farblich hervor.
#
# chmod +x encscan.exs && ./encscan.exs [Optionen] [PFAD ...]
# ./encscan.exs --help

defmodule EncScan do
  @usage """
  encscan.exs – Encodings rekursiv prüfen

  Aufruf: encscan.exs [Optionen] [PFAD ...]        (Standard: .)

    -x, --ext sql,txt         nur diese Dateiendungen
    -e, --exclude NAME        Verzeichnis/Datei ausschließen (mehrfach möglich)
    -a, --hidden              versteckte Dateien/Verzeichnisse einbeziehen
    -b, --binary              auch reine Binärdateitypen auflisten
    -d, --deviants            nur Abweichler und defekte Dateien zeigen
    -s, --sort typ|enc|pfad   Sortierung (Standard: typ)
        --color auto|always|never|256|truecolor
        --light               Farben für hellen Terminal-Hintergrund
        --max-mb N            max. gelesene MB pro Datei (Standard: 16)
        --strict              Exit-Code 1, wenn Abweichler/Defekte gefunden werden

  Markierungen:
     (leer) entspricht der Referenz-Kodierung des Dateityps
     ≈      mehrdeutig (z. B. reines ASCII), passt aber zur Referenz – gedämpfte Farbe
     ✗      Abweichler – invertiert in der Farbe seiner Typ/Encoding-Kombination
     ‼      defekt: gemischte/ungültige Kodierung oder Verdacht auf Doppelkodierung
     ·      Binärdatei
  """

  @default_exclude ~w(.git .svn .hg node_modules _build deps __pycache__ .elixir_ls)

  # Kodierungen, die reines ASCII als Teilmenge enthalten
  @ascii_supersets ~w(utf-8 utf-8-bom windows-1252 iso-8859-1 cp850)
  # Bei Gleichstand bevorzugte Referenz
  @pref ~w(utf-8 utf-8-bom windows-1252 iso-8859-1 cp850 utf-16le utf-16be)
  # Erkennungen ohne Aussagekraft über die "echte" Kodierung
  @weak ~w(ascii leer)

  @high Enum.map(0x80..0xFF, &<<&1>>)
  @c1 Enum.map(0x80..0x9F, &<<&1>>)
  @cp1252_undefined Enum.map([0x81, 0x8D, 0x8F, 0x90, 0x9D], &<<&1>>)
  # äöüÄÖÜß in Latin-1/CP1252 bzw. in CP850 (DOS)
  @latin_de Enum.map([0xE4, 0xF6, 0xFC, 0xC4, 0xD6, 0xDC, 0xDF], &<<&1>>)
  @cp850_de Enum.map([0x84, 0x94, 0x81, 0x8E, 0x99, 0x9A, 0xE1], &<<&1>>)
  # typische Muster doppelt kodierten UTF-8s (Ã¤, Ã¼, Ã„, Â°, …)
  @mojibake [<<0xC3, 0x83, 0xC2>>, <<0xC3, 0x83, 0xC5>>, <<0xC3, 0x83, 0xE2, 0x80>>,
             <<0xC3, 0x82, 0xC2>>]

  @switches [exclude: :keep, ext: :string, hidden: :boolean, binary: :boolean,
             deviants: :boolean, sort: :string, color: :string, light: :boolean,
             max_mb: :integer, strict: :boolean, help: :boolean]
  @aliases [e: :exclude, x: :ext, a: :hidden, b: :binary, d: :deviants, s: :sort, h: :help]

  # ───────────────────────────── Einstieg ─────────────────────────────

  def main(argv) do
    {opts, paths, invalid} = OptionParser.parse(argv, strict: @switches, aliases: @aliases)

    if invalid != [] do
      IO.puts(:stderr, "Unbekannte Option(en): " <> Enum.map_join(invalid, ", ", &elem(&1, 0)))
      System.halt(2)
    end

    if opts[:help] do
      IO.puts(@usage)
      System.halt(0)
    end

    cfg = %{
      exclude: MapSet.new(@default_exclude ++ Keyword.get_values(opts, :exclude)),
      exts: parse_exts(opts[:ext]),
      hidden: opts[:hidden] == true,
      binary: opts[:binary] == true,
      deviants: opts[:deviants] == true,
      sort: opts[:sort] || "typ",
      max: (opts[:max_mb] || 16) * 1024 * 1024
    }

    ctx = color_ctx(opts[:color], opts[:light] == true)
    paths = if paths == [], do: ["."], else: paths

    rows =
      paths
      |> Enum.flat_map(&collect(&1, cfg, true))
      |> Enum.uniq()
      |> Task.async_stream(&analyze(&1, cfg.max),
        ordered: false, timeout: :infinity, max_concurrency: System.schedulers_online() * 2)
      |> Enum.map(fn {:ok, r} -> r end)
      |> classify()

    render(rows, cfg, ctx)

    problems = Enum.count(rows, &(&1.status in [:deviant, :broken]))
    if opts[:strict] && problems > 0, do: System.halt(1)
  end

  defp parse_exts(nil), do: nil

  defp parse_exts(s) do
    s |> String.split(",", trim: true)
    |> Enum.map(&(&1 |> String.trim() |> String.trim_leading(".") |> String.downcase()))
    |> MapSet.new()
  end

  # ─────────────────────────── Dateien sammeln ───────────────────────────

  defp collect(path, cfg, root?) do
    name = Path.basename(path)

    cond do
      not root? and MapSet.member?(cfg.exclude, name) -> []
      not root? and not cfg.hidden and String.starts_with?(name, ".") -> []
      true ->
        case File.lstat(path) do
          {:ok, %File.Stat{type: :directory}} ->
            # list_dir_all liefert auch Namen, die kein gültiges UTF-8 sind
            case :file.list_dir_all(path) do
              {:ok, entries} ->
                entries
                |> Enum.map(&to_bin/1)
                |> Enum.sort()
                |> Enum.flat_map(&collect(Path.join(path, &1), cfg, false))

              {:error, reason} ->
                warn(path, reason)
                []
            end

          {:ok, %File.Stat{type: :regular}} ->
            if cfg.exts == nil or MapSet.member?(cfg.exts, file_type(path)), do: [path], else: []

          # Symlinks, Geräte, Sockets: übersprungen
          {:ok, _} ->
            []

          {:error, reason} ->
            warn(path, reason)
            []
        end
    end
  end

  defp to_bin(n) when is_binary(n), do: n

  # Bei Latin-1-Namenskodierung der VM (z. B. LANG=C) sind Listenelemente Rohbytes
  defp to_bin(n) do
    if :file.native_name_encoding() == :latin1,
      do: :erlang.list_to_binary(n),
      else: List.to_string(n)
  end

  defp warn(path, reason),
    do: IO.puts(:stderr, "Warnung: #{display(path)}: #{:file.format_error(reason)}")

  defp file_type(path) do
    case Path.extname(path) do
      "" -> "(ohne)"
      "." <> ext -> ext |> sanitize() |> String.downcase()
    end
  end

  # ──────────────────────────── Erkennung ────────────────────────────

  defp analyze(path, max) do
    base = %{path: path, type: file_type(path)}

    det =
      case read_head(path, max) do
        {:ok, bin, truncated?} -> detect(bin, truncated?)
        {:error, r} -> %{enc: "unlesbar", notes: [to_string(:file.format_error(r))], broken: true}
      end

    det =
      if String.valid?(Path.basename(path)),
        do: det,
        else: %{det | notes: det.notes ++ ["Dateiname nicht UTF-8"]}

    Map.merge(base, det)
  end

  defp read_head(path, max) do
    case :file.open(path, [:read, :binary, :raw]) do
      {:ok, fd} ->
        res = :file.read(fd, max)
        :file.close(fd)

        case res do
          {:ok, bin} -> {:ok, bin, byte_size(bin) >= max}
          :eof -> {:ok, "", false}
          {:error, r} -> {:error, r}
        end

      {:error, r} ->
        {:error, r}
    end
  end

  defp simple(enc, notes \\ []), do: %{enc: enc, notes: notes, broken: false}

  defp detect(<<>>, _), do: simple("leer")

  defp detect(<<0xEF, 0xBB, 0xBF, rest::binary>>, t) do
    case utf8_check(rest, t) do
      x when x in [:ascii, :utf8] -> utf8_result("utf-8-bom", rest)
      _ -> %{enc: "utf-8-bom", notes: ["ungültige UTF-8-Sequenzen"], broken: true}
    end
  end

  defp detect(<<0xFF, 0xFE, 0, 0, _::binary>>, _), do: simple("utf-32le")
  defp detect(<<0, 0, 0xFE, 0xFF, _::binary>>, _), do: simple("utf-32be")
  defp detect(<<0xFF, 0xFE, _::binary>>, _), do: simple("utf-16le")
  defp detect(<<0xFE, 0xFF, _::binary>>, _), do: simple("utf-16be")

  defp detect(bin, t) do
    cond do
      :binary.match(bin, <<0>>) != :nomatch ->
        detect_nul(bin)

      binary_like?(bin) ->
        simple("binär")

      :binary.match(bin, @high) == :nomatch ->
        simple("ascii")

      true ->
        case utf8_check(bin, t) do
          :ascii -> simple("ascii")
          :utf8 -> utf8_result("utf-8", bin)
          :mixed -> %{enc: "gemischt", notes: ["UTF-8 und 8-Bit-Zeichen in einer Datei"], broken: true}
          :eight_bit -> eight_bit(bin)
        end
    end
  end

  # NUL-Bytes: UTF-16 ohne BOM (Nullen fast nur an geraden bzw. ungeraden Stellen) oder binär
  defp detect_nul(bin) do
    sample = binary_part(bin, 0, min(byte_size(bin), 8192))

    {even, odd, n} =
      for <<a, b <- sample>>, reduce: {0, 0, 0} do
        {e, o, n} -> {e + zero(a), o + zero(b), n + 1}
      end

    cond do
      n > 0 and odd / n > 0.3 and even / n < 0.02 -> simple("utf-16le", ["ohne BOM, geschätzt"])
      n > 0 and even / n > 0.3 and odd / n < 0.02 -> simple("utf-16be", ["ohne BOM, geschätzt"])
      true -> simple("binär")
    end
  end

  # viele Steuerzeichen (außer Tab, LF, VT, FF, CR, ESC) → binär
  @ctrl Enum.map(Enum.to_list(1..8) ++ Enum.to_list(14..26) ++ Enum.to_list(28..31), &<<&1>>)

  defp binary_like?(bin) do
    sample = binary_part(bin, 0, min(byte_size(bin), 8192))
    count(sample, @ctrl) > max(byte_size(sample) * 0.02, 1)
  end

  defp zero(0), do: 1
  defp zero(_), do: 0

  defp utf8_check(bin, truncated?) do
    chunks = String.chunk(bin, :valid)
    chunks = if truncated?, do: drop_partial_tail(chunks), else: chunks

    {utf8?, invalid?} =
      Enum.reduce(chunks, {false, false}, fn c, {u, i} ->
        if String.valid?(c), do: {u or high?(c), i}, else: {u, true}
      end)

    cond do
      utf8? and invalid? -> :mixed
      invalid? -> :eight_bit
      utf8? -> :utf8
      true -> :ascii
    end
  end

  # beim Abschneiden nach max Bytes kann eine UTF-8-Sequenz zerteilt worden sein
  defp drop_partial_tail(chunks) do
    case List.last(chunks) do
      nil -> chunks
      last ->
        if not String.valid?(last) and byte_size(last) <= 3,
          do: List.delete_at(chunks, -1),
          else: chunks
    end
  end

  defp high?(bin), do: :binary.match(bin, @high) != :nomatch
  defp count(bin, pats), do: length(:binary.matches(bin, pats))

  defp utf8_result(enc, bin) do
    if :binary.match(bin, @mojibake) != :nomatch,
      do: %{enc: enc, notes: ["doppelt kodiert? (Ã¤-Muster)"], broken: true},
      else: simple(enc)
  end

  defp eight_bit(bin) do
    s850 = count(bin, @cp850_de)
    s1252 = count(bin, @latin_de)
    undef? = :binary.match(bin, @cp1252_undefined) != :nomatch

    cond do
      s850 > s1252 or (undef? and s850 > 0) -> simple("cp850", ["DOS-Codepage, geschätzt"])
      undef? -> simple("8-bit?", ["unbekannte Codepage"])
      :binary.match(bin, @c1) != :nomatch -> simple("windows-1252")
      # ohne Bytes 0x80–0x9F nicht von CP1252/ISO-8859-15 unterscheidbar
      true -> simple("iso-8859-1")
    end
  end

  # ─────────────────────── Referenz & Abweichler ───────────────────────

  defp classify(results) do
    results
    |> Enum.group_by(& &1.type)
    |> Enum.flat_map(fn {_type, files} ->
      dom = dominant(files)
      Enum.map(files, &Map.merge(&1, %{dominant: dom, status: status(&1, dom)}))
    end)
  end

  # Referenz-Kodierung je Dateityp: die eindeutige Kodierung, zu der die meisten
  # Dateien passen – reine ASCII-Dateien zählen für jede ASCII-kompatible mit.
  defp dominant(files) do
    encs = files |> Enum.reject(& &1.broken) |> Enum.map(& &1.enc)
    text = Enum.reject(encs, &(&1 == "binär"))
    strong = Enum.reject(text, &(&1 in @weak))

    cond do
      strong != [] ->
        strong
        |> Enum.uniq()
        |> Enum.max_by(fn c ->
          {Enum.count(text, &compatible?(&1, c)), Enum.count(strong, &(&1 == c)), -pref_index(c)}
        end)

      text != [] ->
        if "ascii" in text, do: "ascii", else: "leer"

      encs != [] ->
        "binär"

      true ->
        nil
    end
  end

  defp pref_index(c), do: Enum.find_index(@pref, &(&1 == c)) || 99

  defp compatible?(e, e), do: true
  defp compatible?("leer", _), do: true
  defp compatible?("ascii", t), do: t in @ascii_supersets
  defp compatible?("iso-8859-1", "windows-1252"), do: true
  defp compatible?(_, _), do: false

  defp status(f, dom) do
    cond do
      f.broken -> :broken
      f.enc == "binär" and dom in [nil, "binär"] -> :binary
      f.enc == dom -> :normal
      compatible?(f.enc, dom) -> :ambiguous
      true -> :deviant
    end
  end

  # ───────────────────────────── Farben ─────────────────────────────

  defp color_ctx(opt, light?) do
    mode =
      case opt || "auto" do
        "never" -> :none
        "always" -> depth()
        "256" -> :c256
        "truecolor" -> :truecolor
        _ -> if System.get_env("NO_COLOR") in [nil, ""] and IO.ANSI.enabled?(), do: depth(), else: :none
      end

    # {Sättigung, Helligkeit}: normal kräftig, mehrdeutig gleicher Farbton aber gedämpft
    if light?,
      do: %{mode: mode, n: {0.75, 0.33}, a: {0.25, 0.62}, d_l: 0.50},
      else: %{mode: mode, n: {0.62, 0.66}, a: {0.30, 0.40}, d_l: 0.50}
  end

  defp depth,
    do: if(System.get_env("COLORTERM") in ["truecolor", "24bit"], do: :truecolor, else: :c256)

  # Jede Typ/Encoding-Kombination bekommt einen eigenen Farbton. Goldener-Schnitt-
  # Verteilung hält benachbarte Kombinationen weit auseinander; der Rotbereich
  # (335°–25°) bleibt für defekte Dateien reserviert.
  defp hue_map(rows) do
    rows
    |> Enum.flat_map(fn r ->
      case r.status do
        s when s in [:normal, :deviant] -> [{r.type, r.enc}]
        :ambiguous -> [{r.type, r.dominant}]
        _ -> []
      end
    end)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.with_index()
    |> Map.new(fn {k, i} -> {k, 25 + :math.fmod(i * 0.6180339887, 1.0) * 310} end)
  end

  defp style(_r, _hues, %{mode: :none}), do: ""

  defp style(r, hues, ctx) do
    case r.status do
      :normal ->
        {s, l} = ctx.n
        fg(hsl(hues[{r.type, r.enc}], s, l), ctx)

      :ambiguous ->
        {s, l} = ctx.a
        "\e[3m" <> fg(hsl(hues[{r.type, r.dominant}], s, l), ctx)

      :deviant ->
        c = hsl(hues[{r.type, r.enc}], 0.85, ctx.d_l)
        "\e[1m" <> bg(c, ctx) <> fg(contrast(c), ctx)

      :broken ->
        "\e[1m" <> bg({190, 20, 30}, ctx) <> fg({255, 255, 255}, ctx)

      :binary ->
        fg({120, 120, 120}, ctx)
    end
  end

  defp reset(%{mode: :none}), do: ""
  defp reset(_), do: "\e[0m"

  defp fg(rgb, ctx), do: sgr(38, rgb, ctx.mode)
  defp bg(rgb, ctx), do: sgr(48, rgb, ctx.mode)

  defp sgr(base, {r, g, b}, :truecolor), do: "\e[#{base};2;#{r};#{g};#{b}m"
  defp sgr(base, {r, g, b}, :c256), do: "\e[#{base};5;#{16 + 36 * q(r) + 6 * q(g) + q(b)}m"
  defp q(c), do: round(c * 5 / 255)

  # schwarze oder weiße Schrift, je nach Helligkeit des Hintergrunds
  defp contrast({r, g, b}) do
    if (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.55, do: {0, 0, 0}, else: {255, 255, 255}
  end

  defp hsl(h, s, l) do
    c = (1 - abs(2 * l - 1)) * s
    hp = h / 60
    x = c * (1 - abs(:math.fmod(hp, 2) - 1))

    {r, g, b} =
      cond do
        hp < 1 -> {c, x, 0}
        hp < 2 -> {x, c, 0}
        hp < 3 -> {0, c, x}
        hp < 4 -> {0, x, c}
        hp < 5 -> {x, 0, c}
        true -> {c, 0, x}
      end

    m = l - c / 2
    {round((r + m) * 255), round((g + m) * 255), round((b + m) * 255)}
  end

  # ───────────────────────────── Ausgabe ─────────────────────────────

  defp marker(:normal), do: " "
  defp marker(:ambiguous), do: "≈"
  defp marker(:deviant), do: "✗"
  defp marker(:broken), do: "‼"
  defp marker(:binary), do: "·"

  defp status_order(s), do: Enum.find_index([:normal, :ambiguous, :deviant, :broken, :binary], &(&1 == s))

  defp render(rows, cfg, ctx) do
    hues = hue_map(rows)

    visible =
      rows
      |> Enum.reject(&(&1.status == :binary and not cfg.binary))
      |> Enum.filter(&(not cfg.deviants or &1.status in [:deviant, :broken]))
      |> sort_rows(cfg.sort)

    if visible == [] do
      IO.puts("Keine passenden Dateien.")
    else
      we = visible |> Enum.map(&String.length(&1.enc)) |> Enum.max() |> max(8)
      wt = visible |> Enum.map(&String.length(&1.type)) |> Enum.max() |> max(3)

      IO.puts("  " <> String.pad_trailing("ENCODING", we) <> "  " <> String.pad_trailing("TYP", wt) <> "  DATEI")

      Enum.each(visible, fn r ->
        line =
          marker(r.status) <> " " <> String.pad_trailing(r.enc, we) <> "  " <>
            String.pad_trailing(r.type, wt) <> "  " <> display(r.path) <> notes(r)

        IO.puts(style(r, hues, ctx) <> line <> reset(ctx))
      end)
    end

    summary(rows, hues, cfg, ctx)
  end

  defp sort_rows(rows, "enc"), do: Enum.sort_by(rows, &{&1.type, &1.enc, &1.path})
  defp sort_rows(rows, "pfad"), do: Enum.sort_by(rows, & &1.path)
  defp sort_rows(rows, _), do: Enum.sort_by(rows, &{&1.type, &1.path})

  defp notes(r) do
    extra =
      case r.status do
        :ambiguous -> ["≈ #{r.dominant}"]
        :deviant -> ["Referenz: #{r.dominant}"]
        _ -> []
      end

    case extra ++ r.notes do
      [] -> ""
      ns -> "  (" <> Enum.join(ns, "; ") <> ")"
    end
  end

  defp summary(rows, hues, cfg, ctx) do
    groups =
      rows
      |> Enum.group_by(& &1.type)
      |> Enum.reject(fn {_, rs} -> hd(rs).dominant == "binär" and not cfg.binary end)
      |> Enum.sort()

    if groups != [] do
      wt = groups |> Enum.map(fn {t, _} -> String.length(t) end) |> Enum.max()
      IO.puts("\nÜbersicht je Dateityp:")

      Enum.each(groups, fn {type, rs} ->
        chips =
          rs
          |> Enum.group_by(&{&1.status, &1.enc})
          |> Enum.sort_by(fn {{s, _}, l} -> {status_order(s), -length(l)} end)
          |> Enum.map_join(" ", fn {{s, enc}, l} ->
            m = if s == :normal, do: "", else: marker(s)
            style(hd(l), hues, ctx) <> " #{m}#{enc} ×#{length(l)} " <> reset(ctx)
          end)

        IO.puts("  " <> String.pad_trailing(type, wt) <> "  Referenz: " <>
          String.pad_trailing(hd(rs).dominant || "–", 12) <> chips)
      end)
    end

    c = fn s -> Enum.count(rows, &(&1.status == s)) end
    hidden = if cfg.binary, do: 0, else: c.(:binary)

    IO.puts("\n#{length(rows)} Dateien · #{c.(:deviant)} Abweichler · #{c.(:broken)} defekt · " <>
      "#{c.(:ambiguous)} mehrdeutig" <>
      if(hidden > 0, do: " · #{hidden} Binärdateien ausgeblendet (-b)", else: ""))
  end

  defp display(path), do: path |> sanitize() |> String.replace_prefix("./", "")

  # ungültige UTF-8-Namen zur Anzeige als Latin-1 interpretieren
  defp sanitize(bin) do
    if String.valid?(bin), do: bin, else: :unicode.characters_to_binary(bin, :latin1)
  end
end

EncScan.main(System.argv())
