package assets

import "embed"

//go:embed wizard_template.json warp_endpoints.json donate.json support.json l10n contract contract_draft icons
var FS embed.FS

func Read(name string) ([]byte, error) {
	return FS.ReadFile(name)
}
