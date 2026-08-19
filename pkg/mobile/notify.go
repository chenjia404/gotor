package mobile

// safeListener 在持锁外调用，并吞掉回调 panic，避免拖垮客户端。
func safeCall(fn func()) {
	if fn == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	fn()
}

func (t *Tor) snapshotListener() StatusListener {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.listener
}

func (t *Tor) setStatusLocked(percent int, text string) {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	t.bootstrapPercent = percent
	t.statusText = text
}

func (t *Tor) setStatus(percent int, text string) {
	t.mu.Lock()
	t.setStatusLocked(percent, text)
	t.mu.Unlock()
}

func notifyBootstrap(l StatusListener, percent int, msg string) {
	if l == nil {
		return
	}
	safeCall(func() { l.OnBootstrap(percent, msg) })
}

func notifyReady(l StatusListener) {
	if l == nil {
		return
	}
	safeCall(l.OnReady)
}

func notifyError(l StatusListener, msg string) {
	if l == nil {
		return
	}
	safeCall(func() { l.OnError(msg) })
}

func notifyStopped(l StatusListener) {
	if l == nil {
		return
	}
	safeCall(l.OnStopped)
}
