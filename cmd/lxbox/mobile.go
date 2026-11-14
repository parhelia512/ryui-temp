//go:build android

package main

// The RyUI build overlay assigns mobile.Main = main. The application mobile
// package links the JNI bridge and initializes runtime from the Android host.
import (
	_ "github.com/Leadaxe/lxbox/app/mobile"
	_ "github.com/egoist/ryui/mobile"
)
