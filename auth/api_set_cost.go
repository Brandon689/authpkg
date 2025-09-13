package auth

func (a *API) SetBcryptCost(cost int) error {
  if err := validateBcryptCost(cost); err != nil {
    return err
  }
  a.cfg.BcryptCost = cost
  return nil
}
