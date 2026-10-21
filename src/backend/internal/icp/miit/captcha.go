// Package miit -----------------------------
// @file      : captcha.go
// @author    : c1ay
// @time      : 2026/10/15
// -------------------------------------------
// 滑块验证码缺口定位（自 HG-ha/ICP_Query captcha.rs 移植）：
// 大图下采样 1/2 + 颜色量化（每通道高 6 位）→ Top-3 高频色 →
// 垂直连续段 × 水平连续段找「宽高比 0.7~1.4 的近正方形色块」，
// 面积最大者即缺口，返回其左边缘 x（原图坐标）。
package miit

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
)

// MatchSliderOffset 在大图上找纯色近正方形缺口，返回 x 偏移（原图像素）。
func MatchSliderOffset(smallB64, bigB64 string) (int, error) {
	smallRaw, err := base64.StdEncoding.DecodeString(smallB64)
	if err != nil {
		return 0, err
	}
	small, err := decodePNG(smallRaw)
	if err != nil {
		return 0, err
	}
	bigRaw, err := base64.StdEncoding.DecodeString(bigB64)
	if err != nil {
		return 0, err
	}
	bigImg, err := decodePNG(bigRaw)
	if err != nil {
		return 0, err
	}

	sb := small.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	bb := bigImg.Bounds()
	bw, bh := bb.Dx(), bb.Dy()

	w, h := bw/2, bh/2
	if w == 0 || h == 0 {
		return 0, errNoGap
	}

	minSide := int(float32(min(sw, sh)) * 0.25)
	if minSide < 1 {
		minSide = 1
	}
	skipLeft := sw / 4
	goodEnough := minSide * minSide * 3 / 2

	// 下采样 + 量化 → colorID（每通道高 6 位拼 24bit）
	colorID := make([]uint32, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b, _ := bigImg.At(bb.Min.X+x*2, bb.Min.Y+y*2).RGBA()
			q0 := uint32(uint8(r>>8)>>2) << 2
			q1 := uint32(uint8(g>>8)>>2) << 2
			q2 := uint32(uint8(b>>8)>>2) << 2
			colorID[y*w+x] = q0 | q1<<8 | q2<<16
		}
	}

	// 直方图取 Top-3 高频色
	counts := make(map[uint32]int, 128)
	for _, c := range colorID {
		counts[c]++
	}
	ranked := make([]uint32, 0, len(counts))
	for c := range counts {
		ranked = append(ranked, c)
	}
	// 部分排序：取计数前 3
	topN := 3
	if len(ranked) < topN {
		topN = len(ranked)
	}
	if topN == 0 {
		return 0, errNoGap
	}
	for i := 0; i < topN; i++ {
		maxIdx := i
		for j := i + 1; j < len(ranked); j++ {
			if counts[ranked[j]] > counts[ranked[maxIdx]] {
				maxIdx = j
			}
		}
		ranked[i], ranked[maxIdx] = ranked[maxIdx], ranked[i]
	}
	top := ranked[:topN]

	bestArea, bestX := 0, 0
	mask := make([]bool, w*h)
	colRun := make([]int, w*h)

	for _, c := range top {
		for i := range colorID {
			mask[i] = colorID[i] == c
		}
		// 垂直连续长度
		for x := 0; x < w; x++ {
			colRun[x] = boolToInt(mask[x])
		}
		for y := 1; y < h; y++ {
			row, prev := y*w, (y-1)*w
			for x := 0; x < w; x++ {
				if mask[row+x] {
					colRun[row+x] = colRun[prev+x] + 1
				} else {
					colRun[row+x] = 0
				}
			}
		}
		// 逐行找水平连续段（跳过左侧 1/4，滑块本体常在那）
		for y := minSide; y < h; y++ {
			rowBase := y * w
			for x := skipLeft; x < w; {
				if colRun[rowBase+x] < minSide {
					x++
					continue
				}
				s := x
				for x < w && colRun[rowBase+x] >= minSide {
					x++
				}
				runW := x - s
				runH := colRun[rowBase+s]
				if runH <= 0 {
					continue
				}
				ratio := float64(runW) / float64(runH)
				area := runW * runH
				if ratio >= 0.7 && ratio <= 1.4 && area > bestArea {
					bestArea = area
					bestX = s
					if bestArea >= goodEnough {
						return bestX * 2, nil
					}
				}
			}
		}
	}

	if bestArea == 0 {
		return 0, errNoGap
	}
	return bestX * 2, nil
}

type capError string

func (e capError) Error() string { return string(e) }

const errNoGap = capError("未找到缺口")

func decodePNG(raw []byte) (image.Image, error) {
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return img, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
