package main

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var groupRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,31}$`)

var peerKinds = map[string]bool{"": true, "phone": true, "tablet": true, "laptop": true, "desktop": true, "tv": true, "server": true, "other": true}

func validKind(w http.ResponseWriter, k string) bool {
	if !peerKinds[k] {
		errCode(w, http.StatusBadRequest, "peer.bad_kind", nil)
		return false
	}
	return true
}

func validGroup(w http.ResponseWriter, g string) bool {
	if g != "" && !groupRe.MatchString(g) {
		errCode(w, http.StatusBadRequest, "peer.bad_group", nil)
		return false
	}
	return true
}

type bulkIn struct {
	IDs      []string  `json:"ids"`
	Action   string    `json:"action"` // enable | disable | freeze | unfreeze | delete | policy | internet | expires | group
	Minutes  int       `json:"minutes"`
	Policy   string    `json:"policy"`
	Internet bool      `json:"internet"`
	Expires  int       `json:"expires_minutes"`
	Group    string    `json:"group"`
	Schedule *Schedule `json:"schedule"` // action=schedule: nil → saatleri kaldır
}

// handleBulk: seçili cihazlara tek işlemle (tek güvenlik duvarı uygulaması) aynı değişikliği yapar.
// Ya hepsi uygulanır ya hiçbiri: bir hata olursa eski durum korunur.
func (a *App) handleBulk(w http.ResponseWriter, r *http.Request) {
	var in bulkIn
	if !decodeN(w, r, &in, 32<<10) {
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 500 {
		errCode(w, http.StatusBadRequest, "bulk.none_selected", nil)
		return
	}
	in.Group = strings.TrimSpace(in.Group)
	switch in.Action {
	case "enable", "disable", "unfreeze", "delete", "internet":
	case "freeze":
		if in.Minutes < 1 || in.Minutes > maxFreezeMins {
			errCode(w, http.StatusBadRequest, "peer.bad_freeze_time", nil)
			return
		}
	case "expires":
		if in.Expires < 0 || in.Expires > maxExpireMins {
			errCode(w, http.StatusBadRequest, "peer.expiry_too_long", nil)
			return
		}
	case "group":
		if !validGroup(w, in.Group) {
			return
		}
	case "policy", "schedule":
	default:
		errCode(w, http.StatusBadRequest, "bulk.bad_action", nil)
		return
	}

	sched, serr := normalizeSchedule(in.Schedule)
	if serr != nil {
		errOf(w, http.StatusBadRequest, serr)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if in.Action == "policy" && in.Policy != "" && !policyExists(a.pol, in.Policy) {
		errCode(w, http.StatusBadRequest, "policy.not_found", nil)
		return
	}
	sel := map[string]bool{}
	for _, id := range in.IDs {
		sel[id] = true
	}
	now := time.Now()
	next := make([]Peer, 0, len(a.peers))
	var names []string
	var gone []string
	for _, p := range a.peers {
		if !sel[p.ID] {
			next = append(next, p)
			continue
		}
		names = append(names, p.Name)
		switch in.Action {
		case "enable":
			p.Enabled = true
			if p.expired(now) {
				p.ExpiresAt = nil
			}
		case "disable":
			p.Enabled, p.FrozenUntil = false, nil
		case "freeze":
			if p.Enabled {
				t := now.Add(time.Duration(in.Minutes) * time.Minute).UTC()
				p.FrozenUntil = &t
			}
		case "unfreeze":
			p.FrozenUntil = nil
		case "policy":
			p.Policy = in.Policy
		case "internet":
			p.Internet = in.Internet
		case "expires":
			if in.Expires == 0 {
				p.ExpiresAt = nil
			} else {
				if p.expired(now) {
					p.Enabled = true
				}
				t := now.Add(time.Duration(in.Expires) * time.Minute).UTC()
				p.ExpiresAt = &t
			}
		case "group":
			p.Group = in.Group
		case "schedule":
			p.Schedule = sched
		case "delete":
			gone = append(gone, p.ID)
			continue
		}
		next = append(next, p)
	}
	if len(names) != len(sel) {
		errCode(w, http.StatusNotFound, "bulk.not_found", nil)
		return
	}
	pols := a.pol
	removed := 0
	if len(gone) > 0 { // silinen cihazları hedef alan profil kurallarını temizle
		dead := map[string]bool{}
		for _, id := range gone {
			dead[id] = true
		}
		pols = make([]Policy, len(a.pol))
		for i, p := range a.pol {
			np := p
			np.Rules = []Rule{}
			for _, ru := range p.Rules {
				if ru.Target == "device" && dead[ru.Device] {
					removed++
					continue
				}
				np.Rules = append(np.Rules, ru)
			}
			pols[i] = np
		}
	}
	if err := a.applyWith(next, pols); err != nil {
		log.Printf("apply: %v", err)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return
	}
	a.peers, a.pol = next, pols
	if err := a.savePeers(next); err != nil {
		log.Printf("peers.json yazılamadı: %v", err)
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return
	}
	if removed > 0 {
		if err := a.savePolicies(pols); err != nil {
			log.Printf("policies.json yazılamadı: %v", err)
			errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
			return
		}
	}
	a.logReqT(r, "peer_bulk", "log.peer_bulk."+in.Action, map[string]any{"n": len(names), "names": strings.Join(names, ", ")})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(names)})
}
