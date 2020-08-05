package main

import (
    "sync"

    "github.com/emirpasic/gods/sets/treeset"
)

type Similar struct {
    hashs *treeset.Set
    mux   sync.Mutex
}

func NewSimilar() *Similar {
    return &Similar{
        hashs: treeset.NewWithStringComparator(),
    }
}

// Return true if add success (different site)
func (s *Similar) Add(hash string) bool {
    s.mux.Lock()
    bSize := s.hashs.Size()
    s.hashs.Add(hash)
    aSize := s.hashs.Size()
    s.mux.Unlock()
    return aSize > bSize
}
