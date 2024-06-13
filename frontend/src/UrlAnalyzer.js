// frontend/src/UrlAnalyzer.js
import React, { useState } from 'react';
import axios from 'axios';

const UrlAnalyzer = () => {
    const [urls, setUrls] = useState('');
    const [results, setResults] = useState([]);

    const fetchResults = async () => {
        const response = await axios.post('http://localhost:5000/analyze', { urls: urls.split('\n') });
        setResults(response.data);
    };

    const handleInputChange = (e) => {
        setUrls(e.target.value);
    };

    return (
        <div>
            <h1>URL Analyzer</h1>
            <textarea onChange={handleInputChange} placeholder="Enter URLs, one per line" />
            <button onClick={fetchResults}>Analyze</button>
            <div>
                {results.map(result => (
                    <div key={result.url}>
                        <h3>{result.url}</h3>
                        <p>Malicious: {result.malicious ? 'Yes' : 'No'}</p>
                        <p>Score: {result.score}</p>
                        <p>Top Malicious Providers: {result.top_malicious.join(', ')}</p>
                        <p>Top Non-Malicious Providers: {result.top_non_malicious.join(', ')}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default UrlAnalyzer;
