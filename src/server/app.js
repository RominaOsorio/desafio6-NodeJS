import express from 'express'
import morgan from 'morgan'
import cors from 'cors'

import { authToken } from './middlewares/auth.middleware.js'
import { jwtSing, jwtDecode } from './utils/auth/jwt.js'
import { register, getUser, verify } from './models/models.js'

const app = express()
const PORT = process.env.PORT ?? 3000

app.use(cors())
app.use(express.json())
app.use(morgan('dev'))

app.get('/usuarios', authToken, async (req, res) => {
  try {
    const authorization = req.header('Authorization')
    const [token] = authorization.split(' ')
    const { email } = jwtDecode(token)
    const user = await getUser(email)
    res.status(200).json(user)
  } catch (error) {
    res.status(404).json({ status: false, message: error })
  }
})

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body
    await verify(email, password)
    const token = jwtSing({ email })
    res.status(200).json({ status: true, message: token })
  } catch (error) {
    res.status(400).json({ status: false, message: error })
  }
})

app.post('/usuarios', async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body
    await register({ email, password, rol, lenguage })
    res.status(200).json({ status: true, message: 'Usuario ingresado exitosamente' })
  } catch (error) {
    res.status(400).json({ status: false, message: 'No se pudo registrar al usuario' })
  }
})

app.all('*', (req, res) => {
  res.status(404).json({ status: false, message: 'Page not Found' })
})

app.listen(PORT, () => console.log(`Conectado al puerto ${PORT}`))

export default app
