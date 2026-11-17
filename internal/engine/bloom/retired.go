package bloom

// retiredBuiltins identifies only the legacy unattributed hash/label pairs.
// A hash later supplied independently by a feed is not automatically excluded.
var retiredBuiltins = map[string]string{
	"Webshell.PHP.ChinaChopper.v1":    "5443a5160ddfe2eb7c34d3cb38e0787fa3f1396b7ff036c04f494f6f89efec69",
	"Webshell.PHP.ChinaChopper.v2":    "84725350325f17d3d259c77e9238384fa6e8979116e788bc59e51e9e2b024476",
	"Webshell.PHP.Godzilla.v1":        "f73f721598a834241684c7f0709f1dc854897f1f0a149c4ab7dbd11bfdcf4e0d",
	"Webshell.PHP.Godzilla.v2":        "cdcb0409a896aa3f0580a6712da2cf3774775d71c8ee9bc8efc98867a53c69c6",
	"Webshell.PHP.Behinder.v3":        "54877e8108a8d05ec2c6b45db1394a108ef94a8220023a85b9ffdfa811fa15c1",
	"Webshell.PHP.b374k.v3.2.3":       "5df9f6889eb06b9b3e1858a74b43440e0cf0d6350f4a86f917208d1326c7104b",
	"Webshell.PHP.WSO.v2.5":           "2a944888248dca1bb939c32fbc1379105cb8c1e8784cbffdf30dbeab59695d7f",
	"Webshell.PHP.c99shell.v1.0":      "07ca7a9b0c74900a0dc87e682eb616113b2c6bfbe1796d11e5f8f8ef1d234c20",
	"Webshell.PHP.r57shell.v1.4":      "2ee9c7821db2694119934f0d367465369bb9c15d487216a695e2d1743a60a76f",
	"Webshell.JSP.BrowserShell":       "52c0021644c9b9101f3796d66e7368d1844081014e2d3b24f5a2512d7b51b72e",
	"Webshell.ASPX.SpyShell":          "9cf91739c3e218206d87178a946e3364fa1d59fbe9f979805e26c6d2a71bf64c",
	"Trojan.Linux.Mirai.Dropper":      "68a417865239a83850cb171a8fb15bf2830e012351abf19a0a38e88863f6834f",
	"Trojan.Script.ReverseShell.Bash": "42f36cdde08be482e9877b06cb4131df33246ebcb45550a2717a6104fc81bf62",
}

// IsRetiredBuiltin prevents legacy generated corpora from resurrecting unverified seeds.
func IsRetiredBuiltin(hash, label string) bool {
	return retiredBuiltins[label] == hash
}
