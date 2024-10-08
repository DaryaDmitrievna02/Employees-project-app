import { createListenerMiddleware } from '@reduxjs/toolkit'
import { authApi } from '../app/serivices/auth'

export const listenerMiddleware = createListenerMiddleware()

listenerMiddleware.startListening({
  matcher: authApi.endpoints.login.matchFulfilled,
  effect: async (action, listenerApi) => {
    listenerApi.cancelActiveListeners()

    if (action.payload.token || action.payload.jwt) {
      localStorage.setItem('token', action.payload.jwt);
    }
  },
})