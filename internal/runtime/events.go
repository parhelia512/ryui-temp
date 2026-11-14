package runtime

import (
	"encoding/json"
	"sync"
	"time"
)

type Event struct {
	ID uint64 `json:"id"`
	Type string `json:"type"`
	Time time.Time `json:"time"`
	Data json.RawMessage `json:"data"`
}

type EventBatch struct {
	Cursor uint64 `json:"cursor"`
	Events []Event `json:"events"`
	Resync bool `json:"resync"`
}

type eventLog struct {
	mu sync.Mutex
	cursor uint64
	items []Event
	limit int
}

func (l *eventLog) emit(kind string, value any) {
	data, err := json.Marshal(value)
	if err != nil { return }
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cursor++
	l.items = append(l.items, Event{ID:l.cursor, Type:kind, Time:time.Now().UTC(), Data:data})
	limit := l.limit
	if limit <= 0 { limit = 512 }
	if len(l.items) > limit { l.items = append([]Event(nil), l.items[len(l.items)-limit:]...) }
}

func (l *eventLog) poll(after uint64) EventBatch {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := EventBatch{Cursor:l.cursor, Events:[]Event{}}
	if len(l.items)>0 && after>0 && after<l.items[0].ID-1 { out.Resync = true }
	for _, event := range l.items {
		if event.ID>after { event.Data=append(json.RawMessage(nil), event.Data...); out.Events=append(out.Events,event) }
	}
	return out
}
