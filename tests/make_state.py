"""Create fake CPLP host state for tests/fake_gaia.py.

Usage: make_state.py <dir> <name> [initial|updated|nocplp] [version]

  initial  CPLP take 26 (Patch 4): management + VPN patches, VPN ones 'ready'
  updated  take 28 (Patch 5): VPN patches armed, a new login patch, sic:cpd REVERTED,
           cpca now 'jumbofix', Jumbo take raised, CPLP AU component disabled
  nocplp   no cplp command and no URGENT bundle (CPLP never delivered)
"""
import os
import sys

d, name = sys.argv[1], sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "initial"
ver = sys.argv[4] if len(sys.argv) > 4 else "R82.10"
vtag = ver.replace(".", "_")
upd = mode == "updated"

for sub in ("CPshrd/conf", "CPshrd/tmp", "CPshrd/log", "fw1/log", "AutoUpdater/productsConfig", "logs"):
    os.makedirs(f"{d}/{sub}", exist_ok=True)


def w(f, t):
    with open(f"{d}/{f}", "w") as fh:
        fh.write(t)


w("CPshrd/tmp/umis_objects.C", "(\n :DownloadAccess (\n  :allow_download_content (true)\n"
  "  :allow_download_non_security_content (true)\n  :allow_upload_content (true)\n"
  "  :allow_upload_sensitive_content (false)\n )\n)\n")
w("consent_db.txt", "AllowReceivingDataFromCheckPoint 1\nAllowReceivingDataFromCheckPointNonSecurity 1\n"
  "AllowSendingDataToCheckPoint 1\nAllowSendingSensitiveDataToCheckPoint 0\n")

take = 28 if upd else 26
jumbo = 41 if upd else 33
if mode == "nocplp":
    w("cpinfo.txt", f"[CPFC]\n\tHOTFIX_{vtag}_JUMBO_HF_MAIN\tTake:  {jumbo}\n")
    if os.path.exists(f"{d}/cplp_list.txt"):
        os.remove(f"{d}/cplp_list.txt")
    w("au_cplp.txt", "Component urgent_security_updates is not installed\n")
    w("AutoUpdater/productsConfig/products_config.xml", '<Products>\n</Products>\n')
else:
    w("cpinfo.txt", f"""This is Check Point CPinfo Build 914000250 for GAIA
[CPFC]
\tHOTFIX_{vtag}_JUMBO_HF_MAIN\tTake:  {jumbo}
\tBUNDLE_URGENT_SECURITY_UPDATE_{vtag}_AUTOUPDATE\tTake:  {take}
""")
    w("au_cplp.txt", f"""package-version: {take}
package-name: urgent_security_updates_{vtag}_Bundle_T{take}_AutoUpdate.tar
package-installed: true
component-status: {'disabled' if upd else 'enabled'}
""")
    w("AutoUpdater/productsConfig/products_config.xml",
      f'<Products>\n  <Component name="urgent_security_updates" version="{take}" />\n</Products>\n')
    rows = [
        ("cpca:cpca", "jumbofix" if upd else "armed", "1/1", "2026-09-14 10:02:11", "sk185152"),
        ("cpm:fwm", "armed", "1/1", "2026-09-14 10:02:19", "sk185152 sk185169"),
        ("sic:cpd", "reverted" if upd else "armed", "0/1" if upd else "1/1", "2026-09-14 10:02:26", "sk185152"),
        ("sic:msgd", "armed", "1/1", "2026-09-14 10:02:26", "sk185152"),
        ("vpn1:iked", "armed" if upd else "ready", "1/1" if upd else "0/0", "2026-09-14 10:01:50",
         "sk1000117 sk1000118" if upd else ""),
        ("vpn1:vpnd", "armed" if upd else "ready", "2/2" if upd else "0/0", "2026-09-14 10:01:50",
         "sk1000117" if upd else ""),
    ]
    if upd:
        rows.append(("cpm:cpm", "armed", "1/1", "2026-09-30 21:14:03", "sk1000155"))
    out = ["ID(PATCH:PROC)        STATUS     MODE        PIDS    INSTALLED            COMMENT",
           "-" * 74]
    out += [f"{i:<21} {s:<10} livepatch   {p:<7} {t}  {c}".rstrip() for i, s, p, t, c in rows]
    w("cplp_list.txt", "\n".join(out) + "\n")
    w("CPshrd/log/cplp.log", f"[{name}] coverage report: {sum(1 for r in rows if r[1] == 'armed')} armed\n")
print("state written", d, mode, ver)
