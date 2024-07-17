const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(cors({
    origin: ["http://localhost:5173"],
    credentials: true,
}));
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.wxwisw2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        await client.connect();

        const userCollection = client.db("mfsDB").collection("users");
        const transactionCollection = client.db("mfsDB").collection("transactions");

        // JWT-related API
        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
            res.send({ token });
        });

        // Middleware to verify token
        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'Unauthorized access' });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'Unauthorized access' });
                }
                req.decoded = decoded;
                next();
            });
        };

        // Middleware to verify role
        const verifyRole = (role) => {
            return async (req, res, next) => {
                const email = req.decoded.email;
                const user = await userCollection.findOne({ email });
                if (user?.role !== role) {
                    return res.status(403).send({ message: 'Forbidden access' });
                }
                next();
            };
        };

        // User registration
        app.post('/register', async (req, res) => {
            const { name, pin, mobile, email, role } = req.body;
            const hashedPin = await bcrypt.hash(pin, 6);
            const user = { name, pin: hashedPin, mobile, email, role, status: 'pending', balance: role === 'agent' ? 10000 : 0 };
            const result = await userCollection.insertOne(user);
            res.send(result);
        });

        // User login
        app.post('/login', async (req, res) => {
            const { emailOrMobile, pin } = req.body;
            const query = { $or: [{ email: emailOrMobile }, { mobile: emailOrMobile }] };
            const user = await userCollection.findOne(query);
            if (user && await bcrypt.compare(pin, user.pin)) {
                const token = jwt.sign({ email: user.email, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
                res.send({ token });
            } else {
                res.status(401).send({ message: 'Invalid credentials' });
            }
        });

        // Admin endpoints
        app.get('/users', verifyToken, verifyRole('admin'), async (req, res) => {
            const users = await userCollection.find().toArray();
            res.send(users);
        });

        app.put('/users/approve/:id', verifyToken, verifyRole('admin'), async (req, res) => {
            const id = req.params.id;
            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status: 'approved', balance: 40 } });
            res.send(result);
        });

        app.put('/users/block/:id', verifyToken, verifyRole('admin'), async (req, res) => {
            const id = req.params.id;
            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status: 'blocked' } });
            res.send(result);
        });

        app.get('/transactions', verifyToken, verifyRole('admin'), async (req, res) => {
            const transactions = await transactionCollection.find().toArray();
            res.send(transactions);
        });

        // User endpoints
        app.post('/send-money', verifyToken, verifyRole('user'), async (req, res) => {
            const { to, amount, pin } = req.body;
            const fromUser = await userCollection.findOne({ email: req.decoded.email });
            if (fromUser && await bcrypt.compare(pin, fromUser.pin)) {
                if (fromUser.balance >= amount) {
                    const toUser = await userCollection.findOne({ email: to });
                    if (toUser) {
                        const fee = amount > 100 ? 5 : 0;
                        const updatedFromUser = await userCollection.updateOne(
                            { email: req.decoded.email },
                            { $inc: { balance: -(amount + fee) } }
                        );
                        const updatedToUser = await userCollection.updateOne(
                            { email: to },
                            { $inc: { balance: amount } }
                        );
                        const transaction = {
                            from: req.decoded.email,
                            to,
                            amount,
                            type: 'send',
                            fee,
                            date: new Date()
                        };
                        await transactionCollection.insertOne(transaction);
                        res.send({ message: 'Transaction successful' });
                    } else {
                        res.status(404).send({ message: 'Recipient not found' });
                    }
                } else {
                    res.status(400).send({ message: 'Insufficient balance' });
                }
            } else {
                res.status(401).send({ message: 'Invalid PIN' });
            }
        });

        app.post('/cash-out', verifyToken, verifyRole('user'), async (req, res) => {
            const { agent, amount, pin } = req.body;
            const fromUser = await userCollection.findOne({ email: req.decoded.email });
            if (fromUser && await bcrypt.compare(pin, fromUser.pin)) {
                if (fromUser.balance >= amount) {
                    const agentUser = await userCollection.findOne({ email: agent, role: 'agent' });
                    if (agentUser) {
                        const fee = amount * 0.015;
                        const updatedFromUser = await userCollection.updateOne(
                            { email: req.decoded.email },
                            { $inc: { balance: -(amount + fee) } }
                        );
                        const updatedAgentUser = await userCollection.updateOne(
                            { email: agent },
                            { $inc: { balance: amount } }
                        );
                        const transaction = {
                            from: req.decoded.email,
                            to: agent,
                            amount,
                            type: 'cash-out',
                            fee,
                            date: new Date()
                        };
                        await transactionCollection.insertOne(transaction);
                        res.send({ message: 'Cash-out successful' });
                    } else {
                        res.status(404).send({ message: 'Agent not found' });
                    }
                } else {
                    res.status(400).send({ message: 'Insufficient balance' });
                }
            } else {
                res.status(401).send({ message: 'Invalid PIN' });
            }
        });

        app.post('/cash-in', verifyToken, verifyRole('user'), async (req, res) => {
            const { agent, amount, pin } = req.body;
            const toUser = await userCollection.findOne({ email: req.decoded.email });
            if (toUser && await bcrypt.compare(pin, toUser.pin)) {
                const agentUser = await userCollection.findOne({ email: agent, role: 'agent' });
                if (agentUser) {
                    const updatedToUser = await userCollection.updateOne(
                        { email: req.decoded.email },
                        { $inc: { balance: amount } }
                    );
                    const updatedAgentUser = await userCollection.updateOne(
                        { email: agent },
                        { $inc: { balance: -amount } }
                    );
                    const transaction = {
                        from: agent,
                        to: req.decoded.email,
                        amount,
                        type: 'cash-in',
                        fee: 0,
                        date: new Date()
                    };
                    await transactionCollection.insertOne(transaction);
                    res.send({ message: 'Cash-in successful' });
                } else {
                    res.status(404).send({ message: 'Agent not found' });
                }
            } else {
                res.status(401).send({ message: 'Invalid PIN' });
            }
        });

        app.get('/balance', verifyToken, verifyRole('user'), async (req, res) => {
            const user = await userCollection.findOne({ email: req.decoded.email });
            res.send({ balance: user.balance });
        });

        app.get('/transaction-history', verifyToken, verifyRole('user'), async (req, res) => {
            const transactions = await transactionCollection.find({ $or: [{ from: req.decoded.email }, { to: req.decoded.email }] }).sort({ date: -1 }).limit(10).toArray();
            res.send(transactions);
        });

        // Agent endpoints
        app.get('/agent-transactions', verifyToken, verifyRole('agent'), async (req, res) => {
            const transactions = await transactionCollection.find({ $or: [{ from: req.decoded.email }, { to: req.decoded.email }] }).sort({ date: -1 }).limit(10).toArray();
            res.send(transactions);
        });

        app.get('/agent-balance', verifyToken, verifyRole('agent'), async (req, res) => {
            const user = await userCollection.findOne({ email: req.decoded.email });
            res.send({ balance: user.balance });
        });

        app.get('/', (req, res) => {
            res.send('MFS Backend Server is Running');
        });

    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}

run().catch(console.dir);

app.listen(port, () => {
    console.log(`MFS server is running on port ${port}`);
});
