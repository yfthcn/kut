package main

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Schedule: cihazın erişim saatleri (sunucunun yerel saatiyle). Pencerenin dışında:
//   - Scope "tunnel": cihaz sunucudan kalkar (VPN hiç çalışmaz)
//   - Scope "internet": yalnızca internet çıkışı kesilir, VPN ağı çalışır
//
// Pencere From'dan To'ya kadardır; To <= From ise gece yarısını aşar (22:00–06:00 gibi) ve
// gece yarısından sonraki kısım başladığı günün penceresine aittir.
type Schedule struct {
	Days  []int  `json:"days"`  // 0 = Pazar … 6 = Cumartesi
	From  string `json:"from"`  // "HH:MM"
	To    string `json:"to"`    // "HH:MM"
	Scope string `json:"scope"` // "tunnel" | "internet"
}

var hhmmRe = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)

// clockHM: doğrulanmış "SS:DD" dizesini saat ve dakikaya ayırır.
func clockHM(s string) (h, m int) {
	hs, ms, _ := strings.Cut(s, ":")
	h, _ = strconv.Atoi(hs)
	m, _ = strconv.Atoi(ms)
	return h, m
}

func minutesOf(s string) int {
	h, m := clockHM(s)
	return h*60 + m
}

func normalizeSchedule(s *Schedule) (*Schedule, error) {
	if s == nil {
		return nil, nil
	}
	if s.Scope != "tunnel" && s.Scope != "internet" {
		return nil, ue("schedule.bad_scope", nil)
	}
	if !hhmmRe.MatchString(s.From) || !hhmmRe.MatchString(s.To) {
		return nil, ue("schedule.bad_time", nil)
	}
	if s.From == s.To {
		return nil, ue("schedule.same_time", nil)
	}
	seen := map[int]bool{}
	var days []int
	for _, d := range s.Days {
		if d < 0 || d > 6 {
			return nil, ue("schedule.bad_day", nil)
		}
		if !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	if len(days) == 0 {
		return nil, ue("schedule.no_days", nil)
	}
	slices.Sort(days)
	return &Schedule{Days: days, From: s.From, To: s.To, Scope: s.Scope}, nil
}

// allows: o an pencerenin içinde mi.
func (s *Schedule) allows(now time.Time) bool {
	if s == nil {
		return true
	}
	has := func(d int) bool { return slices.Contains(s.Days, d) }
	cur := now.Hour()*60 + now.Minute()
	from, to := minutesOf(s.From), minutesOf(s.To)
	day := int(now.Weekday())
	if from < to {
		return has(day) && cur >= from && cur < to
	}
	// gece yarısını aşan pencere
	if cur >= from {
		return has(day)
	}
	return cur < to && has((day+6)%7)
}

// inWindow: zamanlama yoksa her zaman true.
func (p Peer) inWindow(now time.Time) bool { return p.Schedule.allows(now) }

// scheduleOff: zamanlama VPN'in tamamını şu an kapatıyor mu.
func (p Peer) scheduleOff(now time.Time) bool {
	return p.Schedule != nil && p.Schedule.Scope == "tunnel" && !p.Schedule.allows(now)
}

// inetOn: sunucu bu cihazın internet çıkışına şu an izin veriyor mu (kalıcı izin + saat penceresi).
func (p Peer) inetOn(now time.Time) bool {
	if !p.Internet {
		return false
	}
	return p.Schedule == nil || p.Schedule.Scope != "internet" || p.Schedule.allows(now)
}

// daysText: gün listesinin okunur özeti ("Pzt,Sal" / "Mon,Tue"); yedi gün de seçiliyse "her gün".
func daysText(lang string, days []int) string {
	if len(days) == 7 {
		return T(lang, "access.every_day", nil)
	}
	parts := make([]string, len(days))
	for i, d := range days {
		parts[i] = T(lang, "access.day."+strconv.Itoa(d), nil)
	}
	return strings.Join(parts, ",")
}

// textIn: "Pzt–Cum 09:00–18:00" biçiminde okunur özet.
func (s *Schedule) textIn(lang string) string {
	return daysText(lang, s.Days) + " " + s.From + "–" + s.To
}
