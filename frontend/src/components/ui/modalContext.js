import { createContext, useContext } from 'react'

export const ModalContext = createContext(null)

export function useModal() {
  const value = useContext(ModalContext)
  if (!value) throw new Error('useModal must be used inside ModalProvider')
  return value
}
