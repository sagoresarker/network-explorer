package cache

import (
	"sync"
	"time"

	"github.com/sagoresarker/traceroute-go-portfolio/internal/models"
)

type Cache struct {
	mu       sync.RWMutex
	items    map[string]cacheItem
	duration time.Duration
}

type cacheItem struct {
	value      models.TracerouteResponse
	expiration time.Time
}

func NewCache(duration time.Duration) *Cache {
	c := &Cache{
		items:    make(map[string]cacheItem),
		duration: duration,
	}
	go c.cleanup()
	return c
}

func (c *Cache) Set(key string, value models.TracerouteResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(c.duration),
	}
}

func (c *Cache) Get(key string) (models.TracerouteResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return models.TracerouteResponse{}, false
	}

	if time.Now().After(item.expiration) {
		delete(c.items, key)
		return models.TracerouteResponse{}, false
	}

	return item.value, true
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.items {
			if now.After(item.expiration) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}
