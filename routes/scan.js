const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { createScan, getScansByUser, getScanById } = require('../database');
const { requireAuth } = require('../middleware/auth');
const { scanURL, scanEmail, scanWebsite, getRiskLevel, getRecommendations } = require('../utils/scanner');

// Scan a URL
router.post('/url', requireAuth, (req, res) => {
    try {
        const { target } = req.body;
        if (!target) return res.status(400).json({ error: 'URL is required' });

        const result = scanURL(target);
        const riskLevel = getRiskLevel(result.score);
        const recommendations = getRecommendations(result.score, result.factors, 'url');

        const id = uuidv4();
        createScan({
            id, user_id: req.session.userId, type: 'url', target,
            score: result.score, risk_level: riskLevel,
            details: result.factors, recommendations
        });

        res.json({
            id, type: 'url', target, score: result.score, riskLevel,
            factors: result.factors, recommendations,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('URL scan error:', err);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// Scan email content
router.post('/email', requireAuth, (req, res) => {
    try {
        const { target } = req.body;
        if (!target) return res.status(400).json({ error: 'Email content is required' });

        const result = scanEmail(target);
        const riskLevel = getRiskLevel(result.score);
        const recommendations = getRecommendations(result.score, result.factors, 'email');

        const id = uuidv4();
        createScan({
            id, user_id: req.session.userId, type: 'email', target: target.substring(0, 200),
            score: result.score, risk_level: riskLevel,
            details: result.factors, recommendations
        });

        res.json({
            id, type: 'email', target: target.substring(0, 200),
            score: result.score, riskLevel,
            factors: result.factors, recommendations,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('Email scan error:', err);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// Scan website/domain
router.post('/website', requireAuth, (req, res) => {
    try {
        const { target } = req.body;
        if (!target) return res.status(400).json({ error: 'Domain is required' });

        const result = scanWebsite(target);
        const riskLevel = getRiskLevel(result.score);
        const recommendations = getRecommendations(result.score, result.factors, 'website');

        const id = uuidv4();
        createScan({
            id, user_id: req.session.userId, type: 'website', target,
            score: result.score, risk_level: riskLevel,
            details: result.factors, recommendations
        });

        res.json({
            id, type: 'website', target, score: result.score, riskLevel,
            factors: result.factors, recommendations,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('Website scan error:', err);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// Bulk scan multiple URLs
router.post('/bulk', requireAuth, (req, res) => {
    try {
        const { targets } = req.body;
        if (!targets || !Array.isArray(targets) || targets.length === 0) {
            return res.status(400).json({ error: 'Array of URLs is required' });
        }

        const results = targets.slice(0, 20).map(target => {
            const result = scanURL(target);
            const riskLevel = getRiskLevel(result.score);
            const recommendations = getRecommendations(result.score, result.factors, 'url');

            const id = uuidv4();
            createScan({
                id, user_id: req.session.userId, type: 'bulk', target,
                score: result.score, risk_level: riskLevel,
                details: result.factors, recommendations
            });

            return { id, target, score: result.score, riskLevel, factors: result.factors, recommendations };
        });

        res.json({ results, timestamp: new Date().toISOString() });
    } catch (err) {
        console.error('Bulk scan error:', err);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// Get scan history
router.get('/history', requireAuth, (req, res) => {
    try {
        const scans = getScansByUser(req.session.userId);
        // Return simplified version for history list
        const simplified = scans.map(s => ({
            id: s.id, type: s.type, target: s.target,
            score: s.score, risk_level: s.risk_level, created_at: s.created_at
        }));
        res.json({ scans: simplified });
    } catch (err) {
        console.error('History error:', err);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// Get specific scan report
router.get('/report/:id', requireAuth, (req, res) => {
    try {
        const scan = getScanById(req.params.id, req.session.userId);
        if (!scan) return res.status(404).json({ error: 'Scan not found' });
        res.json(scan);
    } catch (err) {
        console.error('Report error:', err);
        res.status(500).json({ error: 'Failed to fetch report' });
    }
});

module.exports = router;
