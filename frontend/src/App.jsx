import { useState } from 'react'
import { api } from './api'

const initialForm = { email: '', password: '', code: '' }

function App() {
  const [view, setView] = useState('login')
  const [step, setStep] = useState('credentials')
  const [form, setForm] = useState(initialForm)
  const [loginToken, setLoginToken] = useState('')
  const [tokens, setTokens] = useState(() => JSON.parse(localStorage.getItem('auth_tokens') || 'null'))
  const [notice, setNotice] = useState(null)
  const [loading, setLoading] = useState(false)

  const update = (event) => setForm({ ...form, [event.target.name]: event.target.value })
  const showError = (error) => setNotice({ type: 'error', text: error.message })
  const resetFlow = (nextView = 'login') => {
    setView(nextView)
    setStep('credentials')
    setForm(initialForm)
    setLoginToken('')
    setNotice(null)
  }

  async function submit(event) {
    event.preventDefault()
    setLoading(true)
    setNotice(null)
    try {
      if (view === 'register' && step === 'email') {
        await api.confirmEmail(form.email, form.code)
        resetFlow('login')
        setNotice({ type: 'success', text: 'Correo verificado. Ya puedes iniciar sesión.' })
      } else if (view === 'forgot' && step === 'reset') {
        await api.confirmPasswordReset(form.email, form.code, form.password)
        resetFlow('login')
        setNotice({ type: 'success', text: 'Contraseña actualizada. Inicia sesión con ella.' })
      } else if (view === 'register') {
        await api.register(form.email, form.password)
        setStep('email')
        setNotice({ type: 'success', text: 'Te enviamos un código para verificar tu correo.' })
      } else if (view === 'verify-email') {
        await api.confirmEmail(form.email, form.code)
        resetFlow('login')
        setNotice({ type: 'success', text: 'Correo verificado. Ya puedes iniciar sesión.' })
      } else if (view === 'forgot') {
        await api.requestPasswordReset(form.email)
        setStep('reset')
        setNotice({ type: 'success', text: 'Si la cuenta existe, recibirás un código de recuperación.' })
      } else if (view === 'reset') {
        await api.confirmPasswordReset(form.email, form.code, form.password)
        resetFlow('login')
        setNotice({ type: 'success', text: 'Contraseña actualizada. Inicia sesión con ella.' })
      } else if (step === 'credentials') {
        const result = await api.login(form.email, form.password)
        setLoginToken(result.login_token)
        setStep('otp')
        setNotice({ type: 'success', text: 'Código enviado. Revisa tu correo.' })
      } else {
        const result = await api.verifyOtp(loginToken, form.code)
        localStorage.setItem('auth_tokens', JSON.stringify(result))
        setTokens(result)
        setNotice({ type: 'success', text: 'Sesión iniciada correctamente.' })
      }
    } catch (error) {
      showError(error)
    } finally {
      setLoading(false)
    }
  }

  function logout() {
    localStorage.removeItem('auth_tokens')
    setTokens(null)
    resetFlow('login')
    setNotice({ type: 'success', text: 'Sesión cerrada.' })
  }

  if (tokens?.access_token) {
    return <Dashboard tokens={tokens} onLogout={logout} />
  }

  const isOtp = view === 'login' && step === 'otp'
  const isEmailStep = view === 'verify-email' || (view === 'register' && step === 'email')
  const isResetStep = view === 'reset' || (view === 'forgot' && step === 'reset')
  const title = view === 'register' ? 'Crea tu cuenta' : view === 'forgot' || view === 'reset' ? 'Recupera el acceso' : isOtp ? 'Confirma tu acceso' : 'Tu cuenta, bajo control'
  const subtitle = view === 'register' ? 'Empieza con una cuenta protegida por doble factor.' : isOtp ? 'Introduce el código de seis dígitos que enviamos a tu correo.' : isEmailStep ? 'Confirma que este correo te pertenece.' : isResetStep ? 'Elige una contraseña nueva para volver a entrar.' : 'Autenticación simple para sistemas que necesitan confianza.'

  return (
    <main className="shell">
      <section className="brand-panel">
        <div className="brand-mark"><span>+</span></div>
        <p className="eyebrow">Atajo / identidad</p>
        <h1>Acceso que<br /><em>te sigue el ritmo.</em></h1>
        <p className="brand-copy">Una puerta de entrada tranquila para tus cuentas, con verificación en dos pasos cuando realmente importa.</p>
        <div className="security-note"><span className="status-dot" /><span>Protección activa<br /><strong>RSA · OTP · sesiones seguras</strong></span></div>
      </section>

      <section className="form-panel">
        <div className="topline"><span>Área privada</span><span className="live-pill">● Sistema operativo</span></div>
        <div className="form-wrap">
          <div className="form-heading"><p className="kicker">{view === 'login' ? 'Bienvenido de vuelta' : 'Configuración de cuenta'}</p><h2>{title}</h2><p>{subtitle}</p></div>
          {notice && <div className={`notice ${notice.type}`} role="alert">{notice.text}</div>}
          <form onSubmit={submit}>
            {!isOtp && !isEmailStep && !isResetStep && <Field label="Correo electrónico" name="email" type="email" value={form.email} onChange={update} placeholder="tu@correo.com" />}
            {view !== 'forgot' && !isOtp && !isEmailStep && !isResetStep && <Field label="Contraseña" name="password" type="password" value={form.password} onChange={update} placeholder="Mínimo 8 caracteres" />}
            {isOtp && <Field label="Código de verificación" name="code" value={form.code} onChange={update} placeholder="000000" inputMode="numeric" maxLength="6" className="code-input" />}
            {isEmailStep && <Field label="Código de tu correo" name="code" value={form.code} onChange={update} placeholder="000000" inputMode="numeric" maxLength="6" className="code-input" />}
            {isResetStep && <><Field label="Correo electrónico" name="email" type="email" value={form.email} onChange={update} placeholder="tu@correo.com" /><Field label="Código de recuperación" name="code" value={form.code} onChange={update} placeholder="000000" inputMode="numeric" maxLength="6" className="code-input" /><Field label="Nueva contraseña" name="password" type="password" value={form.password} onChange={update} placeholder="Mínimo 8 caracteres" /></>}
            <button className="primary-button" disabled={loading}>{loading ? 'Procesando...' : isOtp ? 'Validar código' : isEmailStep ? 'Verificar correo' : isResetStep ? 'Cambiar contraseña' : view === 'register' ? 'Crear cuenta' : view === 'forgot' ? 'Enviar código' : 'Continuar'}</button>
          </form>
          {view === 'login' && step === 'credentials' && <button className="text-button" onClick={() => resetFlow('forgot')}>¿Olvidaste tu contraseña?</button>}
          <div className="switch-row">{view === 'register' ? <>¿Ya tienes cuenta? <button onClick={() => resetFlow('login')}>Inicia sesión</button></> : <>¿Aún no tienes cuenta? <button onClick={() => resetFlow('register')}>Crear una</button></>}</div>
          {(isOtp || isEmailStep || isResetStep) && <button className="back-button" onClick={() => resetFlow(view === 'reset' || view === 'forgot' ? 'forgot' : view === 'verify-email' ? 'verify-email' : 'login')}>← Volver</button>}
        </div>
        <footer><span>© 2026 Atajo</span><span>Conexión cifrada</span></footer>
      </section>
    </main>
  )
}

function Field({ label, className = '', ...props }) {
  return <label className="field"><span>{label}</span><input required {...props} className={className} /></label>
}

function Dashboard({ tokens, onLogout }) {
  return <main className="dashboard"><div className="dashboard-top"><div className="brand-mark small"><span>+</span></div><span className="live-pill">● Sesión verificada</span><button className="logout" onClick={onLogout}>Cerrar sesión</button></div><section className="welcome"><p className="eyebrow">Panel de identidad</p><h1>Todo en orden.</h1><p>Tu sesión está protegida y lista para continuar.</p><div className="token-card"><span className="token-icon">✓</span><div><strong>Access token activo</strong><small>La API emitió una sesión segura con doble factor.</small></div></div><p className="technical">Token type: {tokens.token_type || 'Bearer'} · Sesión renovable con refresh token</p></section></main>
}

export default App
