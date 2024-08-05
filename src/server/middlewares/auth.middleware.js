import { jwtVerify } from '../utils/auth/jwt.js'

export const authToken = (req, res, next) => {
  const authorization = req.header('Authorization')

  if (authorization === undefined) {
    return res.status(401).json({ message: 'Token no proporcionado' })
  }

  const [bearer, token] = authorization.split(' ')
  if (bearer !== 'Bearer') {
    return res.status(401).json({ message: 'Token mal creado' })
  }

  try {
    jwtVerify(token) && next()
  } catch (error) {
    return res.status(401).json({ message: 'Token no valido' })
  }
}
