module github.com/Leadaxe/lxbox/app

go 1.26.0

require (
	github.com/egoist/ryui v0.0.0
	github.com/sagernet/sing-box v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/egoist/ryui => ./third_party/ryui

replace github.com/sagernet/sing-box => ../core

replace github.com/sagernet/wireguard-go => ../core/submodules/wireguard-go

replace github.com/sagernet/sing-tun => ../core/submodules/sing-tun

replace github.com/sagernet/gvisor => ../core/submodules/gvisor

replace github.com/metacubex/utls => ../core/submodules/utls
