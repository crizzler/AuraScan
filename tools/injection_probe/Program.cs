using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using AntiCopy.Provenance.Configuration;
using AntiCopy.Provenance.Injection;
using AntiCopy.Provenance.Reporting;

// Deterministic golden-span dumper. Input: corpus.json. Output: spans.json.
//
// The oracle is the production detector + production scanner confidence policy with the Card A
// enabled set (instruction-override only). Everything below reads; nothing is written outside the
// output path, and no detector logic is re-implemented here.
internal static class Program
{
    private const string EnabledClass = "instruction-override";

    private sealed class Sample
    {
        public string ClassId;
        public string Path;
        public string Content;
    }

    private static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: probe <corpus.json> <spans.json>");
            return 2;
        }

        List<Sample> samples = LoadCorpus(args[0]);
        if (samples.Count == 0)
        {
            Console.Error.WriteLine("corpus is empty");
            return 2;
        }

        var settings = new InjectionDetectionSettings();
        settings.enabledClasses = new List<string> { EnabledClass };
        var scanner = new InjectionScanner(new RuleBasedDetectionEngine(), settings);
        var engine = new RuleBasedDetectionEngine();

        var builder = new StringBuilder();
        builder.Append("{\n");
        builder.Append("  \"version\": 1,\n");
        builder.Append("  \"anticopy_head\": ").Append(Json(Head())).Append(",\n");
        builder.Append("  \"dotnet_version\": ").Append(Json(Environment.Version.ToString())).Append(",\n");
        builder.Append("  \"regex_culture\": ").Append(Json(CultureInfo.InvariantCulture.Name == string.Empty
            ? "CultureInvariant (RegexOptions.CultureInvariant|IgnoreCase)" : CultureInfo.InvariantCulture.Name)).Append(",\n");
        builder.Append("  \"unicode_culture\": ").Append(Json(CultureInfo.InvariantCulture.Name == string.Empty
            ? "invariant" : CultureInfo.InvariantCulture.Name)).Append(",\n");
        builder.Append("  \"enabled_classes\": [").Append(Json(EnabledClass)).Append("],\n");
        builder.Append("  \"samples\": [\n");

        for (int i = 0; i < samples.Count; i++)
        {
            Sample sample = samples[i];
            if (i > 0) builder.Append(",\n");
            builder.Append("    {\"path\": ").Append(Json(sample.Path));
            builder.Append(", \"class\": ").Append(sample.ClassId == null ? "null" : Json(sample.ClassId));
            builder.Append(", \"hits\": [");

            IList<InjectionMatch> matches = engine.Scan(sample.Content, new List<string> { EnabledClass });
            IList<InjectionEvidence> evidence = scanner.ScanTarget(sample.Path, sample.Content);
            IList<InjectionEvidence> evidenceNoPath = scanner.ScanTarget(string.Empty, sample.Content);

            for (int m = 0; m < matches.Count; m++)
            {
                if (m > 0) builder.Append(", ");
                InjectionMatch match = matches[m];
                builder.Append("{\"class\": ").Append(Json(match.ClassId));
                builder.Append(", \"detector_id\": ").Append(Json(match.DetectorId));
                builder.Append(", \"start\": ").Append(match.StartIndex);
                builder.Append(", \"length\": ").Append(match.Length).Append("}");
            }

            builder.Append("], \"confidence\": ");
            builder.Append(matches.Count == 0 ? "null" : Json(ConfidenceOf(evidence, matches[0].DetectorId)));
            builder.Append(", \"confidence_unknown\": ");
            builder.Append(matches.Count == 0 ? "null" : Json(ConfidenceOf(evidenceNoPath, matches[0].DetectorId)));
            builder.Append("}");
        }

        builder.Append("\n  ]\n}\n");
        File.WriteAllText(args[1], builder.ToString(), new UTF8Encoding(false));
        Console.WriteLine("samples=" + samples.Count);
        return 0;
    }

    private static string ConfidenceOf(IList<InjectionEvidence> evidence, string detectorId)
    {
        for (int i = 0; i < evidence.Count; i++)
        {
            if (string.Equals(evidence[i].DetectorId, detectorId, StringComparison.Ordinal)
                && evidence[i].LineNumber >= 1)
            {
                return evidence[i].Confidence.ToString().ToUpperInvariant();
            }
        }

        return null;
    }

    private static string Head()
    {
        try
        {
            var start = new System.Diagnostics.ProcessStartInfo("git", "-C \"" + Root() + "\" rev-parse HEAD");
            start.RedirectStandardOutput = true;
            start.UseShellExecute = false;
            using (var process = System.Diagnostics.Process.Start(start))
            {
                string text = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return text.Trim();
            }
        }
        catch (Exception)
        {
            return string.Empty;
        }
    }

    private static string Root()
    {
        string configured = Environment.GetEnvironmentVariable("ANTICOPY_ROOT");
        return string.IsNullOrEmpty(configured) ? "/home/arawn/Unity Projects/AntiCopy" : configured;
    }

    private static List<Sample> LoadCorpus(string path)
    {
        var samples = new List<Sample>();
        string json = File.ReadAllText(path, Encoding.UTF8);

        // Minimal JSON walk: the corpus is written by our own exporter with one record per line, so a
        // line scan over the two arrays is exact without a JSON dependency (BCL-only project).
        bool benign = false;
        foreach (string rawLine in json.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.StartsWith("\"samples\"", StringComparison.Ordinal)) { benign = false; continue; }
            if (line.StartsWith("\"benign\"", StringComparison.Ordinal)) { benign = true; continue; }
            if (line.StartsWith("{\"class\"", StringComparison.Ordinal) == false) continue;

            string classId = Extract(line, "\"class\": ");
            string samplePath = Extract(line, "\"path\": ");
            string content = Unescape(Extract(line, "\"content\": "));
            samples.Add(new Sample { ClassId = benign || classId == "null" ? null : classId, Path = samplePath, Content = content });
        }

        return samples;
    }

    private static string Extract(string line, string key)
    {
        int at = line.IndexOf(key, StringComparison.Ordinal);
        if (at < 0) return string.Empty;
        at += key.Length;
        if (at >= line.Length || line[at] != '"') return string.Empty;

        int i = at + 1;
        var builder = new StringBuilder();
        while (i < line.Length)
        {
            char c = line[i];
            if (c == '\\')
            {
                builder.Append(c).Append(line[i + 1]);
                i += 2;
                continue;
            }

            if (c == '"') break;
            builder.Append(c);
            i++;
        }

        return builder.ToString();
    }

    // Decodes the escaped JSON body into the exact text the file holds.
    private static string Unescape(string escaped)
    {
        var builder = new StringBuilder();
        int i = 0;
        while (i < escaped.Length)
        {
            char c = escaped[i];
            if (c != '\\') { builder.Append(c); i++; continue; }

            char kind = escaped[i + 1];
            i += 2;
            switch (kind)
            {
                case 'n': builder.Append('\n'); break;
                case 'r': builder.Append('\r'); break;
                case 't': builder.Append('\t'); break;
                case 'b': builder.Append('\b'); break;
                case 'f': builder.Append('\f'); break;
                case '"': builder.Append('"'); break;
                case '\\': builder.Append('\\'); break;
                case '/': builder.Append('/'); break;
                case 'u':
                    builder.Append((char)Convert.ToInt32(escaped.Substring(i, 4), 16));
                    i += 4;
                    break;
                default: builder.Append(kind); break;
            }
        }

        return builder.ToString();
    }

    private static string Json(string value)
    {
        if (value == null) return "null";
        var builder = new StringBuilder("\"");
        foreach (char c in value)
        {
            switch (c)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (c < 0x20) builder.Append("\\u").Append(((int)c).ToString("x4"));
                    else builder.Append(c);
                    break;
            }
        }

        return builder.Append('"').ToString();
    }
}
