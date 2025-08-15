package structs

import "sync"

type Set struct {
	elements map[string]struct{}
	lock     sync.RWMutex
}

func NewSet() *Set {
	return &Set{elements: make(map[string]struct{})}
}

func (s *Set) Add(value string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.elements[value] = struct{}{}
}

func (s *Set) Remove(value string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.elements, value)
}

func (s *Set) Contains(value string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, ok := s.elements[value]
	return ok
}

func (s *Set) Len() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.elements)
}

func (s *Set) List() []string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	list := make([]string, 0, len(s.elements))
	for v := range s.elements {
		list = append(list, v)
	}
	return list
}
