import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../types';
import { authAPI } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<{ email: string }>;
  verifyCode: (email: string, code: string) => Promise<void>;
  resendCode: (email: string) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('token');
      if (storedToken) {
        try {
          const response = await authAPI.getCurrentUser();
          setUser(response.user);
          setToken(storedToken);
        } catch (error) {
          localStorage.removeItem('token');
          setToken(null);
        }
      }
      setLoading(false);
    };
    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    try {
      const response = await authAPI.login(email, password);
      localStorage.setItem('token', response.token);
      setToken(response.token);
      setUser(response.user);
    } catch (error: any) {
      console.error('Login error in AuthContext:', error);
      throw error; // Re-throw to let Login component handle it
    }
  };

  const register = async (email: string, password: string, name: string) => {
    const response = await authAPI.register(email, password, name);
    // If token is returned, user was created directly (email service not configured)
    if (response.token) {
      localStorage.setItem('token', response.token);
      setToken(response.token);
      setUser(response.user);
      return { email: '' };
    }
    // Otherwise, return email for verification step
    return { email: response.email };
  };

  const verifyCode = async (email: string, code: string) => {
    const response = await authAPI.verifyCode(email, code);
    localStorage.setItem('token', response.token);
    setToken(response.token);
    setUser(response.user);
  };

  const resendCode = async (email: string) => {
    await authAPI.resendCode(email);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, login, register, verifyCode, resendCode, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};



