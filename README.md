# Monitor-CPLP

Watches **Check Point Live Patch (CPLP, sk185114)** on lab Gaia hosts from A-GUI. It shows which live patches are armed, ready, reverted or superseded by a Jumbo, whether each machine has the latest CPLP take, which CVEs that covers, and when any of it changes.

CPLP arrives silently through AutoUpdater (component `urgent_security_updates`) whenever *Download Security* consent is on. In Skillable labs with internet access, a gateway can therefore gain or lose live patches between one class and the next without anyone touching it. This tool makes that visible.

It is built from [Monitor-AutoUpdater](https://github.com/Don-Paterson/Monitor-AutoUpdater) and shares its SSH handling (Clish → expert with the extra-Enter nudge), the lab/machine start-up menu, the per-lab baselines and the dashboard style. The two run side by side: Monitor-AutoUpdater on port 8090 in `C:\Monitor-AutoUpdater`, Monitor-CPLP on port **8091** in `C:\Monitor-CPLP`.

## Quick start

On A-GUI, open PowerShell as Administrator:

```powershell
irm https://raw.githubusercontent.com/Don-Paterson/Monitor-CPLP/main/bootstrap.ps1 | iex
```

The bootstrap installs Python 3.12 if needed, then `flask` and `paramiko`. It downloads the tool to `C:\Monitor-CPLP` and writes `credentials.json` (default `admin` / `Chkp!234`). It then creates a **Monitor-CPLP** desktop shortcut and starts the tool: you pick the lab and machines in the menu, and the dashboard opens at **http://localhost:8091**.

Credential overrides go in environment variables set before the `irm` line: `$env:CPLP_USER`, `$env:CPLP_PASSWORD`, `$env:CPLP_EXPERT`, and `$env:CPLP_RESET='1'` to replace an existing config/credentials.

Nothing is changed on the Check Point hosts. Collection is read-only, and Clish is handled by entering `expert` in each SSH session.

## Choosing the lab and machines

This works exactly as in Monitor-AutoUpdater. Every known lab IP is probed on tcp/22, and each lab is listed with the number of machines that answer, the best match marked **detected**. You then tick machines with `2 4` / `A` / `R` / `N` / `D` / `+ NAME IP [role]` / `P` / `B`, and Enter starts. The choice is saved, so Enter at both menus repeats it.

Shipped labs are in `labs.json` (CCTE, CCSE-ElasticXL, CTPS). Your own go in `labs.local.json`, which the bootstrap never overwrites. To skip the menu, use `--last`, `--lab ccte --hosts A-SMS,A-GW-01`, or `--list-labs`.

## What is collected (expert mode, per poll)

| Section | Command | Used for |
|---|---|---|
| Live patches | `cplp list` | status, mode, PIDS, install time and SK comment per `patch:process` |
| CPLP bundle | `cpinfo -y all \| egrep -i 'URGENT\|JUMBO'` | `BUNDLE_URGENT_SECURITY_UPDATE_<ver>_AUTOUPDATE` take (and version) + Jumbo take |
| AutoUpdater component | `autoupdatercli show urgent_security_updates` + its `products_config.xml` line | enabled / disabled, component version |
| Consent flags | `dbget Allow*` + `DownloadAccess` in `umis_objects.C` | *Download Security* must be on for CPLP to arrive (sk175504) |
| Logs (context) | CPLP-named log files; AutoUpdater log lines mentioning `urgent` | shown in the machine's **Logs** tab |

## How it's judged: `cplp_kb.json`

`cplp_kb.json` is a small knowledge base built from sk185114 (revision shown in the dashboard header):

- **latest take per version:** R82.20 = 29; R82.10 / R82 / R81.20 = 28. A machine below that is flagged **behind**.
- **release history:** Patch 1 (takes 9/10) through Patch 5 (takes 28/29), with the CVE/SK each one covers.
- **status meanings:** armed, ready, jumbofix, nolib, nopatch, unsupp and reverted, used for colours and tooltips.

When Check Point updates sk185114, edit `cplp_kb.json` in the repo (add the new take to `latest_take` and a new entry to `releases`) and push. The bootstrap re-downloads it on every run.

## Dashboard

- **Machine cards:** each shows the CPLP take against the latest (up to date / behind), the CPLP release it corresponds to, the Jumbo take, and counts per status. It also shows the AutoUpdater component state, *Download Security* consent, changes since baseline and alerts. Alerts include a **reverted** patch (CPLP fail-open after crashes), a patch armed on only some PIDs, an `unsupp` build, a take behind latest, the component disabled, consent off, or `cplp` missing.
- **Live patches matrix:** `patch:process` × machine, with the status badge, PIDS, and install time/comment on hover.
- **CVE coverage:** each CVE from the SK × machine, matched through the SK numbers in the `cplp list` COMMENT column. The states are:
  - *armed* or *in Jumbo*.
  - *ready*: waiting for the process.
  - *partial*: armed on some processes, reverted on others.
  - *reverted*.
  - *take too old*: the installed CPLP take predates that patch.
  - *not listed*: no `cplp` entry names that SK, which can be normal (for example VPN fixes on a management server, or a fix already in the Jumbo).
  - *no CPLP*.
- **Change log:** every change, with a severity column. Alerts are reverted patches, a removed CPLP bundle, or `cplp list` starting to fail. Warnings include a take going backwards, consent being turned off, the component being disabled, and partial PIDs. Status improvements (ready → armed, a new patch, a newer take) are marked **ok**.
- **Exports:** **Collect now**, **Status CSV** (the patch/CVE × machine matrix, handy for a lab report) and **Changes CSV**. **Re-baseline** is in each machine's panel.

## Files and logs

```
C:\Monitor-CPLP\
├── server.py               Flask app + poller   (python server.py --once [--last] for a CLI run)
├── config.json             poll interval, dashboard port 8091
├── cplp_kb.json            sk185114 knowledge base (replaced by bootstrap)
├── labs.json / labs.local.json / selection.json     lab profiles, your labs, last choice
├── credentials.json        SSH creds (created by bootstrap, gitignored)
├── cplpmon\                gaia_shell, collector, parsers, kb, differ, store, engine, labs, menu
├── static\dashboard.html
├── data\<lab>\<host>\baseline.json | last_good.json | latest.json | history\*.json
└── logs\<lab>\changes.log  (with severity)   runs.log
```

## Testing without a lab

`tests/fake_gaia.py` is a Paramiko SSH server that behaves like a Gaia host (Clish → expert, plus fake `cplp`, `cpinfo`, `autoupdatercli`, `dbget`). `tests/make_state.py <dir> <name> initial|updated|nocplp [R82.10]` writes a CPLP state:

- `initial`: take 26, VPN patches ready.
- `updated`: take 28, VPN patches armed, a new login patch, `sic:cpd` **reverted**, `cpca` now jumbofix, AU component disabled.
- `nocplp`: no `cplp` command and no URGENT bundle.

## Caveats

- `cplp list` parsing follows the format in sk185114 and finds PIDS and INSTALLED by their shape, so missing columns don't break it. The `autoupdatercli show urgent_security_updates` wording is matched loosely (enabled/disabled). If a real lab shows something unexpected, check **Raw output** in the machine's panel.
- CPLP **audit logs** (Coverage Report / Installed / Applied / Reverted) go to the management server's logs. They are viewed in SmartConsole Logs & Events and are not collected here.
- The tool never triggers a CPLP update. To force one (sk185114), run `autoupdatercli stop; autoupdatercli update_component urgent_security_updates`, then click **Collect now**.
