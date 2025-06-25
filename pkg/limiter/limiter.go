package limiter

import (
	"sync"
)

type Limiter[T any] struct {
	queue        chan T
	workers      int
	orderCounter int64
	orderMutex   sync.Mutex
	MaxRetries   int
}

func NewLimiter[T any](queueSize, workers, maxRetries int) *Limiter[T] {
	return &Limiter[T]{
		queue:        make(chan T, queueSize),
		workers:      workers,
		orderCounter: 0,
		MaxRetries:   maxRetries,
	}
}

func (kl *Limiter[T]) GetNextOrder() int64 {
	kl.orderMutex.Lock()
	defer kl.orderMutex.Unlock()
	kl.orderCounter++
	return kl.orderCounter
}

func (kl *Limiter[T]) StartWorkers(workerFunc func(workerID int, req T)) (stop func()) {
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for i := 0; i < kl.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case req := <-kl.queue:
					workerFunc(workerID, req)
				case <-stopCh:
					return
				}
			}
		}(i)
	}

	return func() {
		close(stopCh)
		wg.Wait()
	}
}

func (kl *Limiter[T]) Enqueue(req T) bool {
	select {
	case kl.queue <- req:
		return true
	default:
		return false
	}
}

func (kl *Limiter[T]) QueueLen() int {
	return len(kl.queue)
}
