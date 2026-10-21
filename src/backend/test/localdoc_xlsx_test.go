package test

import (
	"bytes"
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/service"
	"github.com/xuri/excelize/v2"
)

// 本地文档 XLSX：按 host/name 表头解析出站点与名称。
func TestLocalDocXLSXParse(t *testing.T) {
	f := excelize.NewFile()
	rows := [][]string{
		{"host", "name", "kind", "company"},
		{"xlsx.example.test", "表格应用", "app", "表格公司"},
		{"https://xlsx2.example.test/path", "表格小程序", "miniapp", ""},
	}
	for i, row := range rows {
		for j, v := range row {
			cell, err := excelize.CoordinatesToCellName(j+1, i+1)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.SetCellValue("Sheet1", cell, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatal(err)
	}

	svc := service.NewLocalDocService()
	preview, err := svc.Preview(context.Background(), 1, "assets.xlsx", buf.Bytes())
	if err != nil {
		t.Fatalf("XLSX 文档解析失败: %v", err)
	}
	if preview.Hosts != 2 || preview.Names != 2 {
		t.Fatalf("XLSX 文档计数不符: hosts=%d names=%d", preview.Hosts, preview.Names)
	}
}
