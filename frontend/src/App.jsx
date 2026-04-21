import React, { useState } from 'react';
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

  const handleProcessData = async () => {
    setIsScanning(true);
    setReport(null);
    setErrorMsg(null);

    try {
      let response;
      if (activeTab === 'text') {
        response = await fetch('/api/secure', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: inputText })
        });
      } else if (activeTab === 'image') {
        const formData = new FormData();
        formData.append('image', selectedImage);
        response = await fetch('/api/secure-image', { method: 'POST', body: formData });
      } else if (activeTab === 'csv') {
        const formData = new FormData();
        formData.append('csv', selectedCSV);
        response = await fetch('/api/secure-csv', { method: 'POST', body: formData });
      }

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText); 
      }
      
      const data = await response.json();
      setReport(data);

    } catch (error) {
      setErrorMsg(error.message || "An unexpected network error occurred. Is your Go server running?");
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
      const csvText = await verifyCSV.text();
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
    <div style={{ maxWidth: '850px', width: '100%', padding: '40px 20px', margin: '0 auto', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      
      {/* HEADER */}
      <div style={{ textAlign: 'center', marginBottom: '40px' }}>
        <h1 style={{ fontSize: '3rem', margin: '0 0 10px 0', letterSpacing: '-1px', color: theme.primaryText }}>Vigilant-Vault</h1>
        <p style={{ fontSize: '1.2rem', color: theme.secondaryText, margin: 0 }}>Zero-Trust Gateway for DPDP Compliance</p>
      </div>

      {/* ERROR BANNER */}
      {errorMsg && (
        <div style={{ padding: '16px', backgroundColor: 'rgba(255, 68, 68, 0.1)', color: theme.danger, border: `1px solid ${theme.danger}`, borderRadius: '8px', marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span><strong> ERROR:</strong> {errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} style={{ background: 'none', border: 'none', color: theme.danger, cursor: 'pointer', fontSize: '1.2rem' }}>✖</button>
        </div>
      )}

      {/* MAIN CONTAINER */}
      <div style={{ backgroundColor: theme.cardBg, borderRadius: '12px', border: `1px solid ${theme.border}`, overflow: 'hidden', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}>
        
        {/* TABS */}
        <div style={{ display: 'flex', borderBottom: `1px solid ${theme.border}` }}>
          <button style={getTabStyle('text')} onClick={() => { setActiveTab('text'); setReport(null); setErrorMsg(null); }}>Raw Text</button>
          <button style={getTabStyle('image')} onClick={() => { setActiveTab('image'); setReport(null); setErrorMsg(null); }}>Document OCR</button>
          <button style={getTabStyle('csv')} onClick={() => { setActiveTab('csv'); setReport(null); setErrorMsg(null); }}>Batch CSV</button>
          <button style={{...getTabStyle('verify'), color: activeTab === 'verify' ? theme.success : theme.secondaryText, borderBottomColor: activeTab === 'verify' ? theme.success : 'transparent'}} onClick={() => { setActiveTab('verify'); setReport(null); setErrorMsg(null); }}>Verify Audit</button>
        </div>

        {/* TAB CONTENT */}
        <div style={{ padding: '35px' }}>
          
          {activeTab === 'text' && (
            <div>
              <h3 style={{marginTop: 0, color: theme.primaryText}}>Secure Text Injection</h3>
              <textarea value={inputText} onChange={(e) => setInputText(e.target.value)} placeholder="Paste sensitive data here..." style={{...inputStyle, height: '120px', resize: 'vertical'}} />
            </div>
          )}

          {activeTab === 'image' && (
            <div>
              <h3 style={{marginTop: 0, color: theme.primaryText}}>Vision AI Tokenization</h3>
              <p style={{fontSize: '0.9rem', color: theme.secondaryText, marginBottom: '20px'}}>Upload a physical document. Data will be extracted and stripped of PII.</p>
              <input type="file" accept="image/png, image/jpeg" onChange={(e) => setSelectedImage(e.target.files[0])} style={inputStyle} />
            </div>
          )}

          {activeTab === 'csv' && (
            <div>
              <h3 style={{marginTop: 0, color: theme.primaryText}}>Enterprise Batch Processing</h3>
              <p style={{fontSize: '0.9rem', color: theme.secondaryText, marginBottom: '20px'}}>Upload an entire database. Identities will be mathematically hashed while preserving structural utility.</p>
              <input type="file" accept=".csv" onChange={(e) => setSelectedCSV(e.target.files[0])} style={inputStyle}/>
            </div>
          )}

          {activeTab === 'verify' && (
            <div>
              <h3 style={{marginTop: 0, color: theme.success}}>Government Auditor Portal</h3>
              <p style={{fontSize: '0.9rem', color: theme.secondaryText, marginBottom: '25px'}}>Client-side cryptographic verification. No data leaves your browser.</p>
              
              <label style={{display: 'block', fontWeight: 'bold', color: theme.primaryText, marginBottom: '8px'}}>1. Upload Compliant CSV</label>
              <input type="file" accept=".csv" onChange={(e) => setVerifyCSV(e.target.files[0])} style={{...inputStyle, marginBottom: '20px'}} />
              
              <label style={{display: 'block', fontWeight: 'bold', color: theme.primaryText, marginBottom: '8px'}}>2. Upload JSON Certificate</label>
              <input type="file" accept=".json" onChange={(e) => setVerifyJSON(e.target.files[0])} style={inputStyle} />
            </div>
          )}

          {/* ACTION BUTTON */}
          <button 
            onClick={activeTab === 'verify' ? handleVerifyAudit : handleProcessData} 
            disabled={isScanning}
            style={{ 
              width: '100%', padding: '16px', marginTop: '30px', 
              backgroundColor: activeTab === 'verify' ? (isScanning ? '#0a4a20' : '#106b2f') : (isScanning ? '#1c3e75' : theme.accent), 
              color: 'white', border: 'none', cursor: isScanning ? 'not-allowed' : 'pointer', borderRadius: '8px', 
              fontSize: '1.1rem', fontWeight: 'bold', transition: 'background-color 0.2s' 
            }}
          >
            {isScanning ? '> Establishing secure tunnel...' : (activeTab === 'verify' ? 'Run Integrity Check' : 'Encrypt & Generate Receipt')}
          </button>

          {/* VERIFICATION RESULTS */}
          {activeTab === 'verify' && verifyResult === 'success' && (
            <div style={{ marginTop: '25px', padding: '20px', backgroundColor: 'rgba(0, 255, 65, 0.1)', color: theme.success, border: `1px solid ${theme.success}`, borderRadius: '8px', textAlign: 'center' }}>
              <h2 style={{margin: '0 0 10px 0'}}>AUDIT PASSED</h2>
              <p style={{margin: 0}}>Cryptographic signatures match. Data integrity is absolute.</p>
            </div>
          )}

          {activeTab === 'verify' && verifyResult === 'fail' && (
            <div style={{ marginTop: '25px', padding: '20px', backgroundColor: 'rgba(255, 68, 68, 0.1)', color: theme.danger, border: `1px solid ${theme.danger}`, borderRadius: '8px', textAlign: 'center' }}>
              <h2 style={{margin: '0 0 10px 0'}}>AUDIT FAILED</h2>
              <p style={{margin: 0}}>Signature mismatch. Data has been tampered with or forged.</p>
            </div>
          )}
        </div>
      </div>

      {/* GENERATION REPORT */}
      {report && activeTab !== 'verify' && (
        <div style={{ marginTop: '30px', padding: '30px', backgroundColor: theme.cardBg, borderRadius: '12px', border: `1px solid ${theme.border}`, boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}>
          <h3 style={{marginTop: 0, color: theme.success, display: 'flex', alignItems: 'center', gap: '10px'}}>
            <span style={{display: 'inline-block', width: '10px', height: '10px', backgroundColor: theme.success, borderRadius: '50%'}}></span> 
            {report.message}
          </h3>
          
          {/* TERMINAL STYLE RECEIPT */}
          {report.receipt && (
             <div style={{marginTop: '25px', marginBottom: '25px', padding: '20px', backgroundColor: '#0a0a0a', border: '1px solid #222', borderRadius: '8px', fontFamily: '"Fira Code", monospace', position: 'relative'}}>
                <div style={{position: 'absolute', top: '-10px', left: '20px', backgroundColor: theme.cardBg, padding: '0 10px', fontSize: '0.8rem', color: theme.accent, fontWeight: 'bold'}}>SHA-256 SECURE RECEIPT</div>
                <p style={{margin: '10px 0 5px 0', color: theme.secondaryText}}><span style={{color: '#fff'}}>Timestamp:</span> {report.receipt.timestamp}</p>
                <p style={{margin: '5px 0', color: theme.secondaryText}}><span style={{color: '#fff'}}>Rows Scanned:</span> {report.receipt.rowsProcessed}</p>
                <p style={{margin: '5px 0', color: theme.secondaryText}}><span style={{color: '#fff'}}>Engine:</span> {report.receipt.algorithmVersion}</p>
                <div style={{marginTop: '15px', paddingTop: '15px', borderTop: '1px dashed #333'}}>
                  <p style={{margin: '0 0 5px 0', fontSize: '0.8rem', color: theme.success}}>TRANSACTION FINGERPRINT:</p>
                  <p style={{margin: 0, color: '#fff', wordBreak: 'break-all', fontSize: '0.9rem'}}>{report.receipt.transactionHash}</p>
                </div>
             </div>
          )}

          {activeTab === 'csv' ? (
            <div style={{ display: 'flex', gap: '15px' }}>
              <button onClick={handleDownloadCSV} style={{ flex: 1, padding: '14px', backgroundColor: 'transparent', color: theme.primaryText, border: `1px solid ${theme.accent}`, borderRadius: '6px', cursor: 'pointer', fontSize: '1rem', fontWeight: 'bold' }}>
                 Download Safe Data
              </button>
              <button onClick={handleDownloadReceipt} style={{ flex: 1, padding: '14px', backgroundColor: theme.accent, color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '1rem', fontWeight: 'bold' }}>
                 Download Certificate
              </button>
            </div>
          ) : (
            <div style={{ backgroundColor: '#0a0a0a', padding: '20px', border: '1px solid #222', borderRadius: '8px', fontFamily: 'monospace', whiteSpace: 'pre-wrap', color: '#ccc' }}>
              {report.secureText}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;