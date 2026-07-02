package manifest

import (
	"errors"

	"github.com/shogo82148/androidbinary/apk"
)

var ErrParsePackageInfo = errors.New("failed to parse package info from manifest")

type PackageInfo struct {
	PackageName string
	VersionName string
}

func ParseAPK(path string) (*PackageInfo, error) {
	a, err := apk.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer a.Close()

	packageName := a.PackageName()
	if packageName == "" {
		return nil, ErrParsePackageInfo
	}

	versionName, err := a.Manifest().VersionName.String()
	if err != nil {
		versionName = ""
	}

	return &PackageInfo{
		PackageName: packageName,
		VersionName: versionName,
	}, nil
}
