package structs

import "sync"

type Set[T comparable] struct {
	elements map[T]struct{}
	lock     sync.RWMutex
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{elements: make(map[T]struct{})}
}

func (s *Set[T]) Add(value T) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.elements[value] = struct{}{}
}

func (s *Set[T]) Remove(value T) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.elements, value)
}

func (s *Set[T]) Contains(value T) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, ok := s.elements[value]
	return ok
}

func (s *Set[T]) Len() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.elements)
}

func (s *Set[T]) List() []T {
	s.lock.RLock()
	defer s.lock.RUnlock()
	list := make([]T, 0, len(s.elements))
	for v := range s.elements {
		list = append(list, v)
	}
	return list
}
