package verify

import (
	"encoding/json"
	"html/template"
	"io"
)

// WriteJSON writes the result as indented JSON.
func (r *Result) WriteJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

// WriteHTML writes a single self-contained HTML report: no scripts, no
// external resources, readable offline and printable.
func (r *Result) WriteHTML(w io.Writer) error {
	return reportTmpl.Execute(w, r)
}

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"cls": func(s Status) string {
		return map[Status]string{Verified: "ok", Failed: "bad", Unverifiable: "warn"}[s]
	},
}).Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harborlight pilot verification: {{.Overall}}</title>
<style>
:root{--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--fg:#1f2328;--mut:#59636e;--line:#d1d9e0;--bg:#fff;--soft:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--ok:#3fb950;--bad:#f85149;--warn:#d29922;--fg:#e6edf3;--mut:#9198a1;--line:#3d444d;--bg:#0d1117;--soft:#151b23}}
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg);max-width:980px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.4rem;margin:.2rem 0}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.verdict{border:2px solid;border-radius:8px;padding:1rem 1.2rem;margin:1rem 0}
.verdict.ok{border-color:var(--ok)}.verdict.bad{border-color:var(--bad)}.verdict.warn{border-color:var(--warn)}
.big{font-size:1.6rem;font-weight:700}.ok .big,.st.ok{color:var(--ok)}.bad .big,.st.bad{color:var(--bad)}.warn .big,.st.warn{color:var(--warn)}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;vertical-align:top;padding:.4rem .5rem;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600}.st{font-weight:700;white-space:nowrap}.mut{color:var(--mut)}
.note{background:var(--soft);border-left:3px solid var(--warn);padding:.4rem .7rem;margin-top:.3rem}
code,pre{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;white-space:pre-wrap}
pre{background:var(--soft);padding:.7rem;border-radius:6px}
ul{padding-left:1.2rem}
</style></head><body>
<p class="mut">Harborlight pilot evidence verification report</p>
<h1>{{.Origin}}</h1>
<div class="verdict {{cls .Overall}}"><div class="big">{{.Overall}}</div><div>{{.Summary}}</div></div>
<p class="mut">VERIFIED: every check passed. FAILED: the evidence is provably wrong. UNVERIFIABLE: the verifier could not establish the result (an input was missing, a witness was stale or absent); it is never a pass.</p>

<h2>Checks</h2>
<table><tr><th>Result</th><th>Check</th><th>Detail</th></tr>
{{range .Checks}}<tr><td class="st {{cls .Status}}">{{.Status}}</td><td>{{.Title}}</td><td>{{.Detail}}{{if .Warning}}<div class="note">{{.Warning}}</div>{{end}}</td></tr>
{{end}}</table>

<h2>Checkpoint</h2>
<table><tr><th>Origin</th><td><code>{{.Origin}}</code></td></tr><tr><th>Size</th><td>{{.Size}}</td></tr><tr><th>Root (hex)</th><td><code>{{.Root}}</code></td></tr></table>

<h2>Witnesses</h2>
{{if .Witnesses}}<table><tr><th>Witness</th><th>Operator-run</th><th>Cosignature</th><th>Timestamp (signed by the witness)</th><th>Note</th></tr>
{{range .Witnesses}}<tr><td><code>{{.Name}}</code></td><td>{{if .OperatorControlled}}yes: no independence{{else}}no{{end}}</td><td>{{if .Valid}}{{if .Fresh}}valid, fresh{{else}}valid, not fresh{{end}}{{else if .Present}}INVALID{{else}}absent{{end}}</td><td>{{.Timestamp}}</td><td>{{.Error}}</td></tr>
{{end}}</table>{{else}}<p>No witness results.</p>{{end}}

<h2>Completeness (disclosed, not proven)</h2>
{{with .Completeness}}<table>
<tr><th>Events</th><td>{{.Events}}</td></tr>
<tr><th>Events by source</th><td>{{range $k, $v := .BySource}}<code>{{$k}}</code>: {{$v}}<br>{{end}}</td></tr>
<tr><th>Rejected input lines</th><td>{{.Rejected}} (kept as hashes only)</td></tr>
<tr><th>Batches</th><td>{{.Batches}}</td></tr>
<tr><th>Incomplete batches</th><td>{{range .IncompleteBatch}}{{.}}<br>{{else}}none{{end}}</td></tr>
<tr><th>Duplicate batch entries</th><td>{{range .DuplicateBatch}}{{.}}<br>{{else}}none{{end}}</td></tr>
<tr><th>Source sequence gaps</th><td>{{range .SequenceGaps}}{{.}}<br>{{else}}none{{end}}</td></tr>
<tr><th>Source sequence repeats</th><td>{{range .SequenceRepeats}}{{.}}<br>{{else}}none{{end}}</td></tr>
<tr><th>Log notices</th><td>{{range .LogNotices}}{{.}}<br>{{else}}none{{end}}</td></tr>
<tr><th>Records after the checkpoint</th><td>{{.Uncheckpointed}} (not yet covered, not verified)</td></tr>
</table>{{end}}

<h2>What this result does not show</h2>
<ul>{{range .Disclosures}}<li>{{.}}</li>{{end}}</ul>

<h2>Run manifest</h2>
{{with .Manifest}}<table>
<tr><th>Source</th><td><code>{{.Source}}</code></td></tr>
<tr><th>Verified at</th><td>{{.VerifiedAt}}</td></tr>
<tr><th>Verifier</th><td><code>{{.Verifier}}</code></td></tr>
<tr><th>Pinned log key</th><td><code>{{.LogKey}}</code></td></tr>
<tr><th>Pinned witness keys</th><td>{{range .WitnessKeys}}<code>{{.}}</code><br>{{end}}</td></tr>
<tr><th>Quorum / freshness</th><td>{{.Quorum}} / {{.MaxAge}}</td></tr>
<tr><th>Prior state</th><td><code>{{.PriorState}}</code></td></tr>
<tr><th>Input SHA-256</th><td>{{range $k, $v := .InputSHA256}}<code>{{$k}}</code> <code>{{$v}}</code><br>{{end}}</td></tr>
</table>
<p>Signed checkpoint as verified:</p><pre>{{.CheckpointText}}</pre>{{end}}
<p class="mut">Reproduce: run <code>harborlight-verify</code> with the same source and the same pinned keys. This report is generated output; the evidence is the signed checkpoint and the records, not this page.</p>
</body></html>
`))
