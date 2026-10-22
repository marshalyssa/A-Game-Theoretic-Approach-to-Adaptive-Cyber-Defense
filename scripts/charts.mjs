import { createCanvas } from 'canvas';
import fs from 'fs';

const COLORS = {
    bg: '#0a0e17',
    grid: 'rgba(255, 255, 255, 0.05)',
    text: 'rgba(255, 255, 255, 0.7)',
    baseline: '#94a3b8',
    organized_crime: '#f59e0b',
    apt_state: '#38bdf8',
    insider_threat: '#f43f5e',
    script_kiddie: '#94a3b8'
};

/**
 * Generate a line chart showing utility convergence over episodes
 */
export function generateConvergencePlot(configData, outputPath) {
    const width = 800;
    const height = 450;
    const canvas = createCanvas(width, height);
    const ctx = canvas.getContext('2d');
    const padding = { top: 60, right: 40, bottom: 60, left: 70 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    const data = configData.episodes.map(e => e.defenderUtility);
    const attackerType = configData.attackerType;
    const detectionLevel = configData.detectionLevel;

    // Background
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, width, height);

    // Grid and Axes
    const minVal = Math.min(...data, 0);
    const maxVal = Math.max(...data, 10);
    const range = maxVal - minVal || 1;

    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;
    ctx.font = '12px sans-serif';
    ctx.fillStyle = COLORS.text;

    // Y-axis grid
    for (let i = 0; i <= 5; i++) {
        const y = padding.top + chartHeight - (i / 5) * chartHeight;
        const val = minVal + (i / 5) * range;

        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(width - padding.right, y);
        ctx.stroke();

        ctx.textAlign = 'right';
        ctx.fillText(val.toFixed(1), padding.left - 10, y + 4);
    }

    // X-axis labels
    ctx.textAlign = 'center';
    for (let i = 0; i <= 5; i++) {
        const x = padding.left + (i / 5) * chartWidth;
        const val = Math.round((i / 5) * data.length);
        ctx.fillText(val.toString(), x, height - padding.bottom + 20);
    }

    // Labels
    ctx.font = 'bold 16px sans-serif';
    ctx.fillText(`${attackerType.replace('_', ' ').toUpperCase()} Convergence (@${Math.round(detectionLevel * 100)}% detection)`, width / 2, 30);

    ctx.font = '14px sans-serif';
    ctx.fillText('Episodes', width / 2, height - 15);

    ctx.save();
    ctx.translate(20, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Defender Utility', 0, 0);
    ctx.restore();

    // Line Plot
    const points = data.map((v, i) => ({
        x: padding.left + (i / (data.length - 1)) * chartWidth,
        y: padding.top + chartHeight - ((v - minVal) / range) * chartHeight
    }));

    // Glow Effect
    ctx.shadowBlur = 10;
    ctx.shadowColor = COLORS[attackerType] || COLORS.apt_state;
    ctx.strokeStyle = COLORS[attackerType] || COLORS.apt_state;
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
        ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.stroke();

    // Save
    const buffer = canvas.toBuffer('image/png');
    fs.writeFileSync(outputPath, buffer);
}

/**
 * Generate a grouped bar chart for mean utility across detection levels
 */
export function generateAblationChart(allConfigs, outputPath) {
    const width = 900;
    const height = 500;
    const canvas = createCanvas(width, height);
    const ctx = canvas.getContext('2d');
    const padding = { top: 60, right: 150, bottom: 60, left: 70 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    const attackerTypes = [...new Set(allConfigs.map(c => c.attackerType))];
    const detectionLevels = [...new Set(allConfigs.map(c => c.detectionLevel))].sort((a, b) => a - b);

    const values = allConfigs.map(c => c.summary.meanDefenderUtility);
    const minVal = Math.min(...values, 0);
    const maxVal = Math.max(...values, 10);
    const range = maxVal - minVal || 1;

    // Background
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, width, height);

    // Grid
    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;
    ctx.fillStyle = COLORS.text;
    ctx.font = '12px sans-serif';

    for (let i = 0; i <= 5; i++) {
        const y = padding.top + chartHeight - (i / 5) * chartHeight;
        const val = minVal + (i / 5) * range;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(width - padding.right, y);
        ctx.stroke();
        ctx.textAlign = 'right';
        ctx.fillText(val.toFixed(1), padding.left - 10, y + 4);
    }

    // Grouped Bars
    const groupWidth = chartWidth / detectionLevels.length;
    const barWidth = (groupWidth * 0.8) / attackerTypes.length;

    detectionLevels.forEach((dl, i) => {
        const groupX = padding.left + i * groupWidth;

        ctx.textAlign = 'center';
        ctx.fillText(`${Math.round(dl * 100)}%`, groupX + groupWidth / 2, height - padding.bottom + 20);

        attackerTypes.forEach((at, j) => {
            const config = allConfigs.find(c => c.attackerType === at && c.detectionLevel === dl);
            if (!config) return;

            const val = config.summary.meanDefenderUtility;
            const barHeight = ((val - minVal) / range) * chartHeight;
            const barX = groupX + (groupWidth * 0.1) + j * barWidth;
            const barY = padding.top + chartHeight - barHeight;

            ctx.fillStyle = COLORS[at] || COLORS.apt_state;
            ctx.fillRect(barX, barY, barWidth - 4, barHeight);
        });
    });

    // Legend
    ctx.textAlign = 'left';
    attackerTypes.forEach((at, i) => {
        const lx = width - padding.right + 20;
        const ly = padding.top + 40 + i * 30;

        ctx.fillStyle = COLORS[at] || COLORS.apt_state;
        ctx.fillRect(lx, ly - 12, 15, 15);
        ctx.fillStyle = COLORS.text;
        ctx.fillText(at.replace('_', ' '), lx + 25, ly);
    });

    // Titles
    ctx.font = 'bold 18px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Ablation Study: Detection Coverage vs. Defender Utility', width / 2, 35);
    ctx.font = '14px sans-serif';
    ctx.fillText('Detection Coverage', width / 2, height - 15);

    // Save
    const buffer = canvas.toBuffer('image/png');
    fs.writeFileSync(outputPath, buffer);
}
