// XGBoost Model Training Script
// Based on the research data from 50,000 UPI transactions

class XGBoostTrainer {
    constructor() {
        this.modelParams = {
            learningRate: 0.1,
            maxDepth: 5,
            nEstimators: 100,
            subsample: 0.8,
            colsampleBytree: 0.8,
            randomState: 42
        };
        
        // Training data based on research findings
        this.trainingData = this.generateTrainingData();
    }

    // Generate synthetic training data based on research patterns
    generateTrainingData() {
        const data = [];
        
        // High-risk patterns (fraud = 1)
        for (let i = 0; i < 1000; i++) {
            data.push({
                amount: Math.random() * 500 + 250, // 250-750 range
                transactionType: this.getRandomHighRiskType(),
                paymentGateway: this.getRandomHighRiskGateway(),
                merchantCategory: this.getRandomHighRiskCategory(),
                transactionState: this.getRandomHighRiskState(),
                transactionFrequency: Math.random() * 20 + 10, // High frequency
                daysSinceLastTransaction: Math.random() * 5, // Recent
                fraud: 1
            });
        }
        
        // Low-risk patterns (fraud = 0)
        for (let i = 0; i < 4000; i++) {
            data.push({
                amount: Math.random() * 200 + 50, // 50-250 range
                transactionType: this.getRandomLowRiskType(),
                paymentGateway: this.getRandomLowRiskGateway(),
                merchantCategory: this.getRandomLowRiskCategory(),
                transactionState: this.getRandomLowRiskState(),
                transactionFrequency: Math.random() * 5 + 1, // Low frequency
                daysSinceLastTransaction: Math.random() * 20 + 10, // Not recent
                fraud: 0
            });
        }
        
        return data;
    }

    getRandomHighRiskType() {
        const types = ['Investment', 'Refund', 'Subscription', 'Bill Payment', 'Bank Transfer'];
        return types[Math.floor(Math.random() * types.length)];
    }

    getRandomLowRiskType() {
        const types = ['Purchase', 'Other'];
        return types[Math.floor(Math.random() * types.length)];
    }

    getRandomHighRiskGateway() {
        const gateways = ['ICICI UPI', 'HDFC', 'GooglePay', 'Paytm', 'PhonePe', 'Razor Pay', 'CRED'];
        return gateways[Math.floor(Math.random() * gateways.length)];
    }

    getRandomLowRiskGateway() {
        return 'Other';
    }

    getRandomHighRiskCategory() {
        const categories = ['Home delivery', 'Travel bookings', 'Utilities', 'Financial services and Taxes', 'Donations and Devotion', 'Investment', 'More Services'];
        return categories[Math.floor(Math.random() * categories.length)];
    }

    getRandomLowRiskCategory() {
        const categories = ['Purchases', 'Other'];
        return categories[Math.floor(Math.random() * categories.length)];
    }

    getRandomHighRiskState() {
        const states = ['Himachal Pradesh', 'Rajasthan', 'Meghalaya', 'Bihar', 'Odisha', 'West Bengal'];
        return states[Math.floor(Math.random() * states.length)];
    }

    getRandomLowRiskState() {
        const states = ['Maharashtra', 'Karnataka', 'Tamil Nadu', 'Other'];
        return states[Math.floor(Math.random() * states.length)];
    }

    // Feature engineering
    extractFeatures(data) {
        return {
            amount: data.amount,
            amountCategory: this.categorizeAmount(data.amount),
            isHighRiskAmount: this.isHighRiskAmount(data.amount),
            transactionType: this.encodeTransactionType(data.transactionType),
            isHighRiskType: this.isHighRiskTransactionType(data.transactionType),
            paymentGateway: this.encodePaymentGateway(data.paymentGateway),
            isHighRiskGateway: this.isHighRiskPaymentGateway(data.paymentGateway),
            merchantCategory: this.encodeMerchantCategory(data.merchantCategory),
            isHighRiskMerchant: this.isHighRiskMerchantCategory(data.merchantCategory),
            transactionState: this.encodeTransactionState(data.transactionState),
            isHighRiskState: this.isHighRiskState(data.transactionState),
            transactionFrequency: data.transactionFrequency,
            isFrequentTransaction: this.isFrequentTransaction(data.transactionFrequency),
            daysSinceLastTransaction: data.daysSinceLastTransaction,
            isRecentTransaction: this.isRecentTransaction(data.daysSinceLastTransaction)
        };
    }

    categorizeAmount(amount) {
        if (amount <= 100) return 0;
        if (amount <= 500) return 1;
        if (amount <= 1000) return 2;
        return 3;
    }

    isHighRiskAmount(amount) {
        return amount >= 250 && amount <= 750 ? 1 : 0;
    }

    encodeTransactionType(type) {
        const typeMap = {
            'Purchase': 0,
            'Bank Transfer': 1,
            'Bill Payment': 2,
            'Investment': 3,
            'Refund': 4,
            'Subscription': 5,
            'Other': 6
        };
        return typeMap[type] || 6;
    }

    isHighRiskTransactionType(type) {
        const highRiskTypes = ['Investment', 'Refund', 'Subscription', 'Bill Payment', 'Bank Transfer'];
        return highRiskTypes.includes(type) ? 1 : 0;
    }

    encodePaymentGateway(gateway) {
        const gatewayMap = {
            'ICICI UPI': 0,
            'HDFC': 1,
            'GooglePay': 2,
            'Paytm': 3,
            'PhonePe': 4,
            'Razor Pay': 5,
            'CRED': 6,
            'Other': 7
        };
        return gatewayMap[gateway] || 7;
    }

    isHighRiskPaymentGateway(gateway) {
        const highRiskGateways = ['ICICI UPI', 'HDFC', 'GooglePay', 'Paytm', 'PhonePe', 'Razor Pay', 'CRED'];
        return highRiskGateways.includes(gateway) ? 1 : 0;
    }

    encodeMerchantCategory(category) {
        const categoryMap = {
            'Home delivery': 0,
            'Travel bookings': 1,
            'Utilities': 2,
            'Financial services and Taxes': 3,
            'Donations and Devotion': 4,
            'Investment': 5,
            'More Services': 6,
            'Purchases': 7,
            'Other': 8
        };
        return categoryMap[category] || 8;
    }

    isHighRiskMerchantCategory(category) {
        const highRiskCategories = [
            'Home delivery', 'Travel bookings', 'Utilities', 'Financial services and Taxes', 
            'Donations and Devotion', 'Investment', 'More Services'
        ];
        return highRiskCategories.includes(category) ? 1 : 0;
    }

    encodeTransactionState(state) {
        const stateMap = {
            'Himachal Pradesh': 0,
            'Rajasthan': 1,
            'Meghalaya': 2,
            'Bihar': 3,
            'Odisha': 4,
            'West Bengal': 5,
            'Maharashtra': 6,
            'Karnataka': 7,
            'Tamil Nadu': 8,
            'Other': 9
        };
        return stateMap[state] || 9;
    }

    isHighRiskState(state) {
        const highRiskStates = [
            'Himachal Pradesh', 'Rajasthan', 'Meghalaya', 
            'Bihar', 'Odisha', 'West Bengal'
        ];
        return highRiskStates.includes(state) ? 1 : 0;
    }

    isFrequentTransaction(frequency) {
        return frequency > 10 ? 1 : 0;
    }

    isRecentTransaction(daysSinceLast) {
        return daysSinceLast < 5 ? 1 : 0;
    }

    // Train the model
    train() {
        console.log('Training XGBoost model...');
        
        // Extract features and labels
        const features = [];
        const labels = [];
        
        for (const data of this.trainingData) {
            const featureVector = this.extractFeatures(data);
            features.push([
                featureVector.amount,
                featureVector.amountCategory,
                featureVector.isHighRiskAmount,
                featureVector.transactionType,
                featureVector.isHighRiskType,
                featureVector.paymentGateway,
                featureVector.isHighRiskGateway,
                featureVector.merchantCategory,
                featureVector.isHighRiskMerchant,
                featureVector.transactionState,
                featureVector.isHighRiskState,
                featureVector.transactionFrequency,
                featureVector.isFrequentTransaction,
                featureVector.daysSinceLastTransaction,
                featureVector.isRecentTransaction
            ]);
            labels.push(data.fraud);
        }
        
        // Train multiple decision trees (simplified XGBoost)
        const trees = [];
        const predictions = new Array(features.length).fill(0);
        
        for (let i = 0; i < this.modelParams.nEstimators; i++) {
            // Calculate residuals
            const residuals = labels.map((label, idx) => label - this.sigmoid(predictions[idx]));
            
            // Train a decision tree on residuals
            const tree = this.trainDecisionTree(features, residuals);
            trees.push(tree);
            
            // Update predictions
            for (let j = 0; j < features.length; j++) {
                const treePrediction = this.predictTree(tree, features[j]);
                predictions[j] += this.modelParams.learningRate * treePrediction;
            }
        }
        
        // Calculate feature importance
        const featureImportance = this.calculateFeatureImportance(trees, features);
        
        // Save trained model
        const trainedModel = {
            trees: trees,
            featureImportance: featureImportance,
            modelParams: this.modelParams,
            trainingAccuracy: this.calculateAccuracy(predictions, labels)
        };
        
        console.log('Training completed!');
        console.log('Training accuracy:', trainedModel.trainingAccuracy);
        console.log('Feature importance:', featureImportance);
        
        return trainedModel;
    }

    // Train a single decision tree
    trainDecisionTree(features, residuals) {
        // Simplified decision tree training
        const tree = {
            splits: []
        };
        
        // Create splits based on feature importance
        const importantFeatures = [0, 1, 3, 5, 7, 9, 11, 13]; // Amount, type, gateway, etc.
        
        for (let i = 0; i < 5; i++) { // Max depth of 5
            const featureIdx = importantFeatures[i % importantFeatures.length];
            const threshold = this.findBestThreshold(features, residuals, featureIdx);
            
            tree.splits.push({
                feature: featureIdx,
                threshold: threshold,
                leftValue: this.calculateLeafValue(features, residuals, featureIdx, threshold, 'left'),
                rightValue: this.calculateLeafValue(features, residuals, featureIdx, threshold, 'right')
            });
        }
        
        return tree;
    }

    findBestThreshold(features, residuals, featureIdx) {
        const values = features.map(f => f[featureIdx]).sort((a, b) => a - b);
        return values[Math.floor(values.length / 2)];
    }

    calculateLeafValue(features, residuals, featureIdx, threshold, side) {
        const relevantResiduals = features.map((f, idx) => {
            if (side === 'left') {
                return f[featureIdx] <= threshold ? residuals[idx] : 0;
            } else {
                return f[featureIdx] > threshold ? residuals[idx] : 0;
            }
        }).filter(r => r !== 0);
        
        return relevantResiduals.length > 0 ? 
            relevantResiduals.reduce((a, b) => a + b, 0) / relevantResiduals.length : 0;
    }

    predictTree(tree, features) {
        let prediction = 0;
        
        for (const split of tree.splits) {
            if (features[split.feature] <= split.threshold) {
                prediction += split.leftValue;
            } else {
                prediction += split.rightValue;
            }
        }
        
        return prediction;
    }

    calculateFeatureImportance(trees, features) {
        const importance = new Array(15).fill(0);
        
        for (const tree of trees) {
            for (const split of tree.splits) {
                importance[split.feature] += Math.abs(split.leftValue) + Math.abs(split.rightValue);
            }
        }
        
        // Normalize
        const maxImportance = Math.max(...importance);
        return importance.map(imp => imp / maxImportance);
    }

    calculateAccuracy(predictions, labels) {
        let correct = 0;
        for (let i = 0; i < predictions.length; i++) {
            const predicted = predictions[i] > 0.5 ? 1 : 0;
            if (predicted === labels[i]) {
                correct++;
            }
        }
        return correct / predictions.length;
    }

    sigmoid(x) {
        return 1 / (1 + Math.exp(-x));
    }
}

// Train the model and save it
const trainer = new XGBoostTrainer();
const trainedModel = trainer.train();

// Save the trained model to localStorage for use in the main application
localStorage.setItem('trainedXGBoostModel', JSON.stringify(trainedModel));

console.log('Trained model saved to localStorage!');
console.log('Model can now be used in the fraud detection system.');

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { XGBoostTrainer, trainedModel };
} else {
    window.XGBoostTrainer = XGBoostTrainer;
    window.trainedModel = trainedModel;
} 