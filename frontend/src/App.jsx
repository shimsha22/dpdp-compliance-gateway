import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('csv');
  const [isScanning, setIsScanning] = useState(false);
  const [report, setReport] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null); 

  const [inputText, setInputText] = useState('');
  const [selectedImage, setSelectedImage] = useState(null);
  const [selectedCSV, setSelectedCSV] = useState(null); 

  const [verifyCSV, setVerifyCSV] = useState(null);
  const [verifyJSON, setVerifyJSON] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null); 
  
  const API_BASE_URL = "https://dpdp-compliance-gateway.onrender.com";

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/verify-audit`).catch(() => {});
  }, []);

  const handleProcessData = async () => {
    setIsScanning(true);
    setReport(null);
    setErrorMsg(null);

    try {
      let response;
      if (activeTab === 'text') {
        response = await fetch(`${API_BASE_URL}/api/secure`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: inputText })
        });
      } else if (activeTab === 'image') {
        const formData = new FormData();
        formData.append('image', selectedImage);
        response = await fetch(`${API_BASE_URL}/api/secure-image`, { method: 'POST', body: formData });
      } else if (activeTab === 'csv') {
        const formData = new FormData();
        formData.append('csv', selectedCSV);
        response = await fetch(`${API_BASE_URL}/api/secure-csv`, { method: 'POST', body: formData });
      }

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText); 
      }
      
      const data = await response.json();
      setReport(data);

    } catch (error) {
      setErrorMsg(error.message || "Network Error: Ensure your Render Backend is live.");
    } finally {
      setIsScanning(false);
    }
  };

  const handleVerifyAudit = async () => {
    if (!verifyCSV || !verifyJSON) {
      setErrorMsg("Please upload both the Compliant CSV and the Audit JSON.");
      return;
    }
    
    setIsScanning(true);
    setVerifyResult(null);
    setErrorMsg(null);

    try {
      
      const rawCsv = await verifyCSV.text();
      const csvText = rawCsv.replace(/\r/g, '').trim(); 

      const jsonText = await verifyJSON.text();
      const receipt = JSON.parse(jsonText);

      const payload = `${receipt.timestamp}|${receipt.rowsProcessed}|${receipt.algorithmVersion}|${csvText}`;
      
      const msgBuffer = new TextEncoder().encode(payload);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const calculatedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      if (calculatedHash === receipt.transactionHash) {
        setVerifyResult('success');
      } else {
        setVerifyResult('fail');
      }
    } catch (error) {
      console.error("Verification error:", error);
      setVerifyResult('invalid');
    } finally {
      setIsScanning(false);
    }
  };

  const handleDownloadCSV = () => {
    const blob = new Blob([report.secureText], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'VigilantVault_Compliant_Data.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const handleDownloadReceipt = () => {
    const receiptJSON = JSON.stringify(report.receipt, null, 2);
    const blob = new Blob([receiptJSON], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'DPDP_Audit_Certificate.json';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const theme = {
    bg: '#050505',
    cardBg: '#121212',
    border: '#2a2a2a',
    primaryText: '#f5f5f5',
    secondaryText: '#888888',
    accent: '#4285F4', 
    success: '#00FF41', 
    danger: '#ff4444'
  };

  const getTabStyle = (tabName) => ({
    padding: '14px 24px', cursor: 'pointer', flex: 1, 
    border: 'none', borderBottom: activeTab === tabName ? `3px solid ${theme.accent}` : `3px solid transparent`,
    backgroundColor: activeTab === tabName ? '#1a1a1a' : theme.cardBg,
    color: activeTab === tabName ? theme.accent : theme.secondaryText,
    fontWeight: activeTab === tabName ? '600' : '500',
    fontSize: '0.95rem',
    transition: 'all 0.3s ease'
  });

  const inputStyle = {
    width: '100%', padding: '12px', backgroundColor: '#1a1a1a', color: theme.primaryText,
    border: `1px solid ${theme.border}`, borderRadius: '6px', boxSizing: 'border-box'
  };

  return (
    <div style={{ maxWidth: '850px', width: '100%', padding: '40px 20px', margin: '0 auto', fontFamily: 'system-ui, sans-serif', color: theme.primaryText, backgroundColor: theme.bg }}>
      
      <div style={{ textAlign: 'center', marginBottom: '40px' }}>
        <h1 style={{ fontSize: '3rem', margin: '0 0 10px 0', letterSpacing: '-1px' }}>Vigilant-Vault</h1>
        <p style={{ fontSize: '1.2rem', color: theme.secondaryText, margin: 0 }}>Zero-Trust Gateway for DPDP Compliance</p>
      </div>

      {errorMsg && (
        <div style={{ padding: '16px', backgroundColor: 'rgba(255, 68, 68, 0.1)', color: theme.danger, border: `1px solid ${theme.danger}`, borderRadius: '8px', marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span><strong> ERROR:</strong> {errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} style={{ background: 'none', border: 'none', color: theme.danger, cursor: 'pointer', fontSize: '1.2rem' }}>✖</button>
        </div>
      )}

      <div style={{ backgroundColor: theme.cardBg, borderRadius: '12px', border: `1px solid ${theme.border}`, overflow: 'hidden' }}>
        <div style={{ display: 'flex', borderBottom: `1px solid ${theme.border}` }}>
          <button style={getTabStyle('text')} onClick={() => setActiveTab('text')}>Raw Text</button>
          <button style={getTabStyle('image')} onClick={() => setActiveTab('image')}>Document OCR</button>
          <button style={getTabStyle('csv')} onClick={() => setActiveTab('csv')}>Batch CSV</button>
          <button style={{...getTabStyle('verify'), color: activeTab === 'verify' ? theme.success : theme.secondaryText}} onClick={() => setActiveTab('verify')}>Verify Audit</button>
        </div>

        <div style={{ padding: '35px' }}>
          {activeTab === 'text' && (
            <textarea value={inputText} onChange={(e) => setInputText(e.target.value)} placeholder="Paste sensitive data here..." style={{...inputStyle, height: '120px'}} />
          )}

          {activeTab === 'image' && (
            <input type="file" accept="image/*" onChange={(e) => setSelectedImage(e.target.files[0])} style={inputStyle} />
          )}

          {activeTab === 'csv' && (
            <input type="file" accept=".csv" onChange={(e) => setSelectedCSV(e.target.files[0])} style={inputStyle}/>
          )}

          {activeTab === 'verify' && (
            <div>
              <label style={{display: 'block', marginBottom: '8px'}}>1. Upload Compliant CSV</label>
              <input type="file" accept=".csv" onChange={(e) => setVerifyCSV(e.target.files[0])} style={{...inputStyle, marginBottom: '20px'}} />
              <label style={{display: 'block', marginBottom: '8px'}}>2. Upload JSON Certificate</label>
              <input type="file" accept=".json" onChange={(e) => setVerifyJSON(e.target.files[0])} style={inputStyle} />
            </div>
          )}

          <button 
            onClick={activeTab === 'verify' ? handleVerifyAudit : handleProcessData} 
            disabled={isScanning}
            style={{ 
              width: '100%', padding: '16px', marginTop: '30px', 
              backgroundColor: isScanning ? theme.secondaryText : (activeTab === 'verify' ? theme.success : theme.accent), 
              color: 'white', border: 'none', cursor: 'pointer', borderRadius: '8px', fontWeight: 'bold' 
            }}
          >
            {isScanning ? 'Processing...' : (activeTab === 'verify' ? 'Verify Integrity' : 'Secure Data')}
          </button>

          {/* VERIFICATION RESULT UI */}
          {activeTab === 'verify' && verifyResult && (
            <div style={{
              marginTop: '20px', padding: '15px', borderRadius: '8px', textAlign: 'center',
              border: `1px solid ${verifyResult === 'success' ? theme.success : theme.danger}`,
              backgroundColor: verifyResult === 'success' ? 'rgba(0, 255, 65, 0.1)' : 'rgba(255, 68, 68, 0.1)',
              color: verifyResult === 'success' ? theme.success : theme.danger
            }}>
              {verifyResult === 'success' && <strong> Integrity Verified: Data is Authentic</strong>}
              {verifyResult === 'fail' && <strong>Verification Failed: Data has been tampered with</strong>}
              {verifyResult === 'invalid' && <strong> Error: Invalid Certificate Format</strong>}
            </div>
          )}
        </div>
      </div>

      {report && (
        <div style={{ marginTop: '30px', padding: '20px', backgroundColor: theme.cardBg, borderRadius: '12px', border: `1px solid ${theme.border}` }}>
          <h3 style={{color: theme.success}}>{report.message}</h3>
          <div style={{ backgroundColor: '#000', padding: '15px', borderRadius: '6px', fontSize: '0.9rem', overflowX: 'auto', marginBottom: '20px' }}>
            <pre style={{ color: '#ccc' }}>{report.secureText}</pre>
          </div>
          {(activeTab === 'csv' || activeTab === 'text' || activeTab === 'image') && (
            <div style={{ display: 'flex', gap: '10px' }}>
              <button onClick={handleDownloadCSV} style={{ flex: 1, padding: '10px', backgroundColor: 'transparent', border: `1px solid ${theme.accent}`, color: theme.accent, borderRadius: '6px', cursor: 'pointer' }}>Download Secured Data</button>
              <button onClick={handleDownloadReceipt} style={{ flex: 1, padding: '10px', backgroundColor: theme.accent, border: 'none', color: 'white', borderRadius: '6px', cursor: 'pointer' }}>Download Certificate</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;