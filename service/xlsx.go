package service

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"
)

// readXLSXRows 读取第一个工作表的全部行（单元格去空白）。
// 只用于导入预览，调用方负责行数上限与业务解析。
func readXLSXRows(data []byte) ([][]string, error) {
	if len(data) == 0 {
		return nil, errors.New("XLSX 文件为空")
	}
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("XLSX 解析失败: %w", err)
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, errors.New("XLSX 没有工作表")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, fmt.Errorf("读取工作表 %s 失败: %w", sheets[0], err)
	}
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		clean := make([]string, len(row))
		for i, cell := range row {
			clean[i] = strings.TrimSpace(cell)
		}
		out = append(out, clean)
	}
	return out, nil
}
