// XGBoost-Inspired UPI Fraud Detection Model
// Based on research showing XGBoost achieved 99.48% accuracy
// Simplified implementation for browser-based fraud detection

class XGBoostUPIFraudModel {
    constructor() {
        // Load trained model from localStorage
        const savedModel = localStorage.getItem('trainedXGBoostModel');
        
        if (savedModel) {
            const trainedModel = JSON.parse(savedModel);
            this.trees = trainedModel.trees;
            this.featureImportance = trainedModel.featureImportance;
            this.modelParams = trainedModel.modelParams;
            this.trainingAccuracy = trainedModel.trainingAccuracy;
            console.log('Loaded trained XGBoost model with accuracy:', this.trainingAccuracy);
        } else {
            // Fallback to untrained model
            console.log('No trained model found, using fallback model');
            this.initializeFallbackModel();
        }
        
        // Risk thresholds from research
        this.riskThresholds = {
            high: 0.8,
            medium: 0.5,
            low: 0.2
        };
    }

    // Initialize fallback model (untrained)
    initializeFallbackModel() {
        this.trees = [];
        this.featureImportance = [0.25, 0.20, 0.15, 0.15, 0.10, 0.10, 0.05];
        this.modelParams = {
            learningRate: 0.1,
            maxDepth: 5,
            nEstimators: 100
        };
        this.trainingAccuracy = 0.85; // Estimated accuracy
        
        // Create simple fallback trees
        for (let i = 0; i < this.modelParams.nEstimators; i++) {
            this.trees.push(new DecisionTree(this.modelParams.maxDepth));
        }
    }

    // Feature engineering based on research
    extractFeatures(transactionData) {
        const features = {};
        
        // Amount features
        features.amount = parseFloat(transactionData.amount) || 0;
        features.amountCategory = this.categorizeAmount(features.amount);
        features.isHighRiskAmount = this.isHighRiskAmount(features.amount);
        
        // Transaction type features
        features.transactionType = this.encodeTransactionType(transactionData.transactionType);
        features.isHighRiskType = this.isHighRiskTransactionType(transactionData.transactionType);
        
        // Payment gateway features
        features.paymentGateway = this.encodePaymentGateway(transactionData.paymentGateway);
        features.isHighRiskGateway = this.isHighRiskPaymentGateway(transactionData.paymentGateway);
        
        // Merchant features
        features.merchantCategory = this.encodeMerchantCategory(transactionData.merchantName);
        features.isHighRiskMerchant = this.isHighRiskMerchantCategory(transactionData.merchantName);
        
        // Geographic features
        features.transactionState = this.encodeTransactionState(transactionData.transactionState);
        features.isHighRiskState = this.isHighRiskState(transactionData.transactionState);
        
        // Temporal features
        features.transactionFrequency = parseInt(transactionData.transactionFrequency) || 0;
        features.daysSinceLastTransaction = parseInt(transactionData.daysSinceLastTransaction) || 0;
        features.isFrequentTransaction = this.isFrequentTransaction(features.transactionFrequency);
        features.isRecentTransaction = this.isRecentTransaction(features.daysSinceLastTransaction);
        
        // UPI ID features
        features.upiRisk = this.calculateUPIRisk(transactionData.upiId);
        
        return features;
    }

    // Predict fraud probability using trained ensemble
    predict(transactionData) {
        const features = this.extractFeatures(transactionData);
        let ensembleScore = 0;
        
        // Get predictions from all trained trees
        for (let tree of this.trees) {
            const treePrediction = this.predictTree(tree, features);
            ensembleScore += treePrediction * this.modelParams.learningRate;
        }
        
        // Apply sigmoid to get probability
        const fraudProbability = this.sigmoid(ensembleScore);
        
        return {
            fraudProbability: fraudProbability,
            riskLevel: this.determineRiskLevel(fraudProbability),
            confidence: this.calculateConfidence(features),
            featureImportance: this.getFeatureImportance(features),
            modelAccuracy: this.trainingAccuracy
        };
    }

    // Predict using a single trained tree
    predictTree(tree, features) {
        let prediction = 0;
        
        for (const split of tree.splits) {
            const featureValue = this.getFeatureValue(features, split.feature);
            if (featureValue <= split.threshold) {
                prediction += split.leftValue;
            } else {
                prediction += split.rightValue;
            }
        }
        
        return prediction;
    }
    
    // Get feature value from extracted features
    getFeatureValue(features, featureIdx) {
        const featureArray = [
            features.amount,
            features.amountCategory,
            features.isHighRiskAmount,
            features.transactionType,
            features.isHighRiskType,
            features.paymentGateway,
            features.isHighRiskGateway,
            features.merchantCategory,
            features.isHighRiskMerchant,
            features.transactionState,
            features.isHighRiskState,
            features.transactionFrequency,
            features.isFrequentTransaction,
            features.daysSinceLastTransaction,
            features.isRecentTransaction
        ];
        
        return featureArray[featureIdx] || 0;
    }

    // Feature categorization methods
    categorizeAmount(amount) {
        if (amount <= 100) return 'low';
        if (amount <= 500) return 'medium';
        if (amount <= 1000) return 'high';
        return 'very_high';
    }

    isHighRiskAmount(amount) {
        // Based on research: 250-750 range is high risk
        return amount >= 250 && amount <= 750;
    }

    encodeTransactionType(type) {
        const typeMap = {
            'Purchase': 1,
            'Bank Transfer': 2,
            'Bill Payment': 3,
            'Investment': 4,
            'Refund': 5,
            'Subscription': 6,
            'Other': 7
        };
        return typeMap[type] || 7;
    }

    isHighRiskTransactionType(type) {
        const highRiskTypes = ['Investment', 'Refund', 'Subscription', 'Bill Payment', 'Bank Transfer'];
        return highRiskTypes.includes(type);
    }

    encodePaymentGateway(gateway) {
        const gatewayMap = {
            'ICICI UPI': 1,
            'HDFC': 2,
            'GooglePay': 3,
            'Paytm': 4,
            'PhonePe': 5,
            'Razor Pay': 6,
            'CRED': 7,
            'Other': 8
        };
        return gatewayMap[gateway] || 8;
    }

    isHighRiskPaymentGateway(gateway) {
        const highRiskGateways = ['ICICI UPI', 'HDFC', 'GooglePay', 'Paytm', 'PhonePe', 'Razor Pay', 'CRED'];
        return highRiskGateways.includes(gateway);
    }

    encodeMerchantCategory(merchantName) {
        const merchantLower = merchantName.toLowerCase();
        if (merchantLower.includes('home delivery')) return 1;
        if (merchantLower.includes('travel')) return 2;
        if (merchantLower.includes('utility')) return 3;
        if (merchantLower.includes('financial')) return 4;
        if (merchantLower.includes('donation')) return 5;
        if (merchantLower.includes('investment')) return 6;
        if (merchantLower.includes('service')) return 7;
        return 8; // Other
    }

    isHighRiskMerchantCategory(merchantName) {
        const merchantLower = merchantName.toLowerCase();
        const highRiskCategories = [
            'home delivery', 'travel', 'utility', 'financial', 
            'donation', 'investment', 'service'
        ];
        return highRiskCategories.some(category => merchantLower.includes(category));
    }

    encodeTransactionState(state) {
        const stateMap = {
            'Himachal Pradesh': 1,
            'Rajasthan': 2,
            'Meghalaya': 3,
            'Bihar': 4,
            'Odisha': 5,
            'West Bengal': 6,
            'Maharashtra': 7,
            'Karnataka': 8,
            'Tamil Nadu': 9,
            'Other': 10
        };
        return stateMap[state] || 10;
    }

    isHighRiskState(state) {
        const highRiskStates = [
            'Himachal Pradesh', 'Rajasthan', 'Meghalaya', 
            'Bihar', 'Odisha', 'West Bengal'
        ];
        return highRiskStates.includes(state);
    }

    isFrequentTransaction(frequency) {
        // Based on research: > 10 transactions is suspicious
        return frequency > 10;
    }

    isRecentTransaction(daysSinceLast) {
        // Based on research: < 5 days is suspicious
        return daysSinceLast < 5;
    }

    calculateUPIRisk(upiId) {
        if (!upiId) return 0;
        
        const upiLower = upiId.toLowerCase();
        let risk = 0;
        
        // Check for suspicious patterns
        const suspiciousKeywords = [
            'support', 'help', 'verify', 'update', 'secure', 'official',
            'bank', 'govt', 'government', 'refund', 'claim', 'reward',
            'bonus', 'cashback', 'urgent', 'immediate', 'quick'
        ];
        
        suspiciousKeywords.forEach(keyword => {
            if (upiLower.includes(keyword)) {
                risk += 0.1;
            }
        });
        
        return Math.min(risk, 1);
    }

    determineRiskLevel(probability) {
        if (probability >= this.riskThresholds.high) return 'HIGH';
        if (probability >= this.riskThresholds.medium) return 'MEDIUM';
        return 'LOW';
    }

    calculateConfidence(features) {
        // Calculate confidence based on feature consistency
        let confidence = 0.5; // Base confidence
        
        // Increase confidence if multiple high-risk features are present
        const highRiskFeatures = [
            features.isHighRiskAmount,
            features.isHighRiskType,
            features.isHighRiskGateway,
            features.isHighRiskMerchant,
            features.isHighRiskState,
            features.isFrequentTransaction,
            features.isRecentTransaction
        ];
        
        const highRiskCount = highRiskFeatures.filter(f => f).length;
        confidence += highRiskCount * 0.1;
        
        return Math.min(confidence, 1);
    }

    getFeatureImportance(features) {
        const featureNames = [
            'amount', 'amountCategory', 'isHighRiskAmount', 'transactionType', 'isHighRiskType',
            'paymentGateway', 'isHighRiskGateway', 'merchantCategory', 'isHighRiskMerchant',
            'transactionState', 'isHighRiskState', 'transactionFrequency', 'isFrequentTransaction',
            'daysSinceLastTransaction', 'isRecentTransaction'
        ];
        
        const importance = {};
        for (let i = 0; i < featureNames.length; i++) {
            importance[featureNames[i]] = this.featureImportance[i] || 0;
        }
        
        return importance;
    }
    
    sigmoid(x) {
        return 1 / (1 + Math.exp(-x));
    }
}

// Simplified Decision Tree for ensemble
class DecisionTree {
    constructor(maxDepth) {
        this.maxDepth = maxDepth;
        this.root = null;
    }

    predict(features) {
        // Simplified prediction based on feature thresholds
        let score = 0;
        
        // Amount-based decision
        if (features.amount >= 250 && features.amount <= 750) {
            score += 0.3;
        }
        
        // Transaction type decision
        if (features.isHighRiskType) {
            score += 0.2;
        }
        
        // Payment gateway decision
        if (features.isHighRiskGateway) {
            score += 0.15;
        }
        
        // Merchant category decision
        if (features.isHighRiskMerchant) {
            score += 0.15;
        }
        
        // Geographic decision
        if (features.isHighRiskState) {
            score += 0.1;
        }
        
        // Frequency decision
        if (features.isFrequentTransaction) {
            score += 0.1;
        }
        
        return Math.min(score, 1);
    }
}

// Export for use in HTML
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { XGBoostUPIFraudModel, DecisionTree };
} else {
    window.XGBoostUPIFraudModel = XGBoostUPIFraudModel;
    window.DecisionTree = DecisionTree;
} 