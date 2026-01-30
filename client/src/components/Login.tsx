import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import Logo from './Logo';
import './Login.css';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLogin, setIsLogin] = useState(true);
  const [name, setName] = useState('');
  const [verificationStep, setVerificationStep] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [pendingEmail, setPendingEmail] = useState('');
  const [isResending, setIsResending] = useState(false);
  const { login, register, verifyCode, resendCode } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      if (isLogin) {
        await login(email, password);
        navigate('/');
      } else {
        if (verificationStep) {
          // Verify code
          if (!verificationCode || verificationCode.length !== 6) {
            setError('Please enter a valid 6-digit code');
            return;
          }
          await verifyCode(pendingEmail, verificationCode);
          navigate('/');
        } else {
          // Step 1: Register and send verification code
          if (!name) {
            setError('Name is required');
            return;
          }
          const result = await register(email, password, name);
          // If email is returned, we need verification
          if (result.email) {
            setPendingEmail(result.email);
            setVerificationStep(true);
          } else {
            // If no email returned, account was created directly (email service not configured)
            navigate('/');
          }
        }
      }
    } catch (err: any) {
      console.error('Auth error:', err);
      if (err.response?.data?.message) {
        setError(err.response.data.message);
      } else if (err.message) {
        setError(err.message);
      } else if (err.code === 'ERR_NETWORK' || err.code === 'ECONNREFUSED') {
        setError('Cannot connect to server. Please check if the server is running.');
      } else {
        setError('An error occurred. Please try again.');
      }
    }
  };

  const handleResendCode = async () => {
    try {
      setIsResending(true);
      setError('');
      await resendCode(pendingEmail);
      setError('');
      alert('Verification code resent! Please check your email.');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to resend code. Please try again.');
    } finally {
      setIsResending(false);
    }
  };

  const handleBackToRegister = () => {
    setVerificationStep(false);
    setVerificationCode('');
    setPendingEmail('');
    setError('');
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <Logo size="large" showText={true} text="File Box" />
          <p>
            {isLogin 
              ? 'Sign in to your account' 
              : verificationStep 
                ? 'Verify your email' 
                : 'Create a new account'}
          </p>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          {verificationStep ? (
            <>
              <div className="verification-info">
                <p>We've sent a 6-digit verification code to:</p>
                <p className="verification-email">{pendingEmail}</p>
                <p className="verification-hint">Please check your email and enter the code below.</p>
              </div>
              <div className="verification-code-input">
                <input
                  type="text"
                  placeholder="000000"
                  value={verificationCode}
                  onChange={(e) => {
                    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                    setVerificationCode(value);
                    setError('');
                  }}
                  className="login-input code-input"
                  maxLength={6}
                  autoFocus
                />
              </div>
              {error && <div className="error-message">{error}</div>}
              <button type="submit" className="login-button">
                Verify & Create Account
              </button>
              <div className="verification-actions">
                <button
                  type="button"
                  onClick={handleResendCode}
                  disabled={isResending}
                  className="resend-button"
                >
                  {isResending ? 'Sending...' : 'Resend Code'}
                </button>
                <button
                  type="button"
                  onClick={handleBackToRegister}
                  className="back-button-link"
                >
                  Back to Registration
                </button>
              </div>
            </>
          ) : (
            <>
              {!isLogin && (
                <input
                  type="text"
                  placeholder="Full Name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="login-input"
                />
              )}
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="login-input"
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="login-input"
              />
              {error && <div className="error-message">{error}</div>}
              <button type="submit" className="login-button">
                {isLogin ? 'Sign In' : 'Sign Up'}
              </button>
            </>
          )}
        </form>
        <div className="login-footer">
          {!verificationStep && (
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setError('');
                setVerificationStep(false);
                setVerificationCode('');
                setPendingEmail('');
              }}
              className="toggle-button"
            >
              {isLogin ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default Login;

