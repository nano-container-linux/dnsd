package server

import internalsrv "dnsd/internal/dnsd"

func Run(configDir string) error {
	return internalsrv.Run(configDir)
}

func Validate(configDir string) error {
	return internalsrv.Validate(configDir)
}
