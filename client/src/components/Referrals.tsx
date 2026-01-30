import React, { useState, useEffect } from 'react';
import { ReferralIcon, CopyIcon, LoadingIcon } from './Icons';
import './Referrals.css';

const Referrals: React.FC = () => {
  const [referralCode, setReferralCode] = useState<string>('');
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadReferralData();
  }, []);

  const loadReferralData = async () => {
    try {
      // TODO: Implement API call
      setLoading(false);
    } catch (error) {
      console.error('Error loading referral data:', error);
      setLoading(false);
    }
  };

  const copyReferralCode = () => {
    navigator.clipboard.writeText(referralCode);
    alert('Referral code copied!');
  };

  return (
    <div className="referrals">
      <div className="referrals-header">
        <h2><ReferralIcon size={24} color="currentColor" /> Referral Program</h2>
      </div>
      {loading ? (
        <div className="loading-state">
          <LoadingIcon size={40} color="#6b7280" />
          <p>Loading referral information...</p>
        </div>
      ) : (
        <div className="referrals-content">
          <div className="referral-card">
            <h3>Your Referral Code</h3>
            <div className="referral-code-display">
              <code>{referralCode || 'Loading...'}</code>
              <button onClick={copyReferralCode} className="btn-icon">
                <CopyIcon size={16} color="currentColor" />
              </button>
            </div>
            <p>Share this code with friends to earn rewards!</p>
          </div>
          {stats && (
            <div className="referral-stats">
              <div className="stat-item">
                <h4>{stats.totalReferrals || 0}</h4>
                <p>Total Referrals</p>
              </div>
              <div className="stat-item">
                <h4>{stats.completedReferrals || 0}</h4>
                <p>Completed</p>
              </div>
              <div className="stat-item">
                <h4>{stats.rewardedReferrals || 0}</h4>
                <p>Rewarded</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Referrals;

