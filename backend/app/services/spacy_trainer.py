import json
import random
import spacy
from spacy.training import Example
from spacy.util import minibatch, compounding
import logging
from pathlib import Path
from typing import List, Dict, Tuple
import warnings
warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SkillExtractionTrainer:
    def __init__(self, training_data_path: str, model_output_path: str):
        """
        Initialize the spaCy trainer for skill extraction
        
        Args:
            training_data_path: Path to the training data JSON file
            model_output_path: Path to save the trained model
        """
        self.training_data_path = training_data_path
        self.model_output_path = model_output_path
        self.training_data = []
        self.nlp = None
        
    def load_training_data(self):
        """Load training data from JSON file"""
        try:
            with open(self.training_data_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            # Convert to spaCy format: (text, {"entities": [(start, end, label)]})
            self.training_data = []
            for item in raw_data:
                text = item['text']
                entities = item['entities']
                
                # Validate entities
                validated_entities = []
                for start, end, label in entities:
                    if start < end <= len(text):
                        validated_entities.append((start, end, label))
                
                if validated_entities:
                    self.training_data.append((text, {"entities": validated_entities}))
            
            logger.info(f"Loaded {len(self.training_data)} training examples")
            
        except Exception as e:
            logger.error(f"Error loading training data: {e}")
            raise
    
    def create_model(self, model_name: str = None) -> spacy.Language:
        """Create a new spaCy model or load existing one"""
        if model_name and Path(model_name).exists():
            logger.info(f"Loading existing model: {model_name}")
            nlp = spacy.load(model_name)
        else:
            logger.info("Creating new blank English model")
            nlp = spacy.blank("en")
        
        # Add NER component if it doesn't exist
        if "ner" not in nlp.pipe_names:
            ner = nlp.add_pipe("ner")
        else:
            ner = nlp.get_pipe("ner")
        
        # Add labels to the NER component
        ner.add_label("SKILL")
        
        return nlp
    
    def train_model(self, 
                   n_iter: int = 100, 
                   dropout: float = 0.2,
                   batch_size: int = 4,
                   learn_rate: float = 0.001):
        """
        Train the spaCy NER model
        
        Args:
            n_iter: Number of training iterations
            dropout: Dropout rate for regularization
            batch_size: Batch size for training
            learn_rate: Learning rate
        """
        # Load training data
        self.load_training_data()
        
        # Create model
        self.nlp = self.create_model()
        
        # Get the NER component
        ner = self.nlp.get_pipe("ner")
        
        # Only train NER
        pipe_exceptions = ["ner", "trf_wordpiecer", "trf_tok2vec"]
        other_pipes = [pipe for pipe in self.nlp.pipe_names if pipe not in pipe_exceptions]
        
        # Disable other components during training
        with self.nlp.disable_pipes(*other_pipes):
            # Initialize optimizer
            optimizer = self.nlp.resume_training()
            optimizer.learn_rate = learn_rate
            
            logger.info(f"Starting training for {n_iter} iterations...")
            
            for iteration in range(n_iter):
                logger.info(f"Iteration {iteration + 1}/{n_iter}")
                
                # Shuffle training data
                random.shuffle(self.training_data)
                losses = {}
                
                # Create batches
                batches = minibatch(self.training_data, size=compounding(4.0, 32.0, 1.001))
                
                for batch in batches:
                    examples = []
                    for text, annotations in batch:
                        doc = self.nlp.make_doc(text)
                        example = Example.from_dict(doc, annotations)
                        examples.append(example)
                    
                    # Update model
                    self.nlp.update(examples, drop=dropout, losses=losses, sgd=optimizer)
                
                logger.info(f"Losses: {losses}")
                
                # Save intermediate model every 20 iterations
                if (iteration + 1) % 20 == 0:
                    temp_path = f"{self.model_output_path}_iter_{iteration + 1}"
                    self.save_model(temp_path)
                    
                    # Evaluate model
                    self.evaluate_model()
        
        logger.info("Training completed!")
    
    def evaluate_model(self, test_data: List[Tuple] = None):
        """
        Evaluate the trained model
        
        Args:
            test_data: Test data in spaCy format. If None, uses training data sample
        """
        if test_data is None:
            # Use a sample of training data for evaluation
            test_data = random.sample(self.training_data, min(50, len(self.training_data)))
        
        correct = 0
        total = 0
        
        logger.info("Evaluating model...")
        
        for text, annotations in test_data:
            doc = self.nlp(text)
            predicted_entities = [(ent.start_char, ent.end_char, ent.label_) for ent in doc.ents]
            actual_entities = annotations["entities"]
            
            # Simple evaluation: count exact matches
            for pred in predicted_entities:
                if pred in actual_entities:
                    correct += 1
            
            total += len(actual_entities)
        
        precision = correct / max(total, 1)
        logger.info(f"Evaluation - Precision: {precision:.3f} ({correct}/{total})")
        
        return precision
    
    def save_model(self, output_path: str = None):
        """
        Save the trained model
        
        Args:
            output_path: Path to save the model. If None, uses default path
        """
        if output_path is None:
            output_path = self.model_output_path
        
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.nlp.to_disk(output_dir)
        logger.info(f"Model saved to: {output_dir}")
        
        # Save model metadata
        metadata = {
            "model_type": "skill_extraction",
            "training_examples": len(self.training_data),
            "entities": ["SKILL"],
            "language": "en"
        }
        
        with open(output_dir / "metadata.json", 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
    
    def test_model(self, test_text: str):
        """
        Test the model on a sample text
        
        Args:
            test_text: Text to extract skills from
        """
        if self.nlp is None:
            logger.error("Model not trained yet!")
            return
        
        doc = self.nlp(test_text)
        
        logger.info(f"\nTest text: {test_text}")
        logger.info("Extracted skills:")
        
        skills = []
        for ent in doc.ents:
            if ent.label_ == "SKILL":
                skills.append({
                    "text": ent.text,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "confidence": ent._.confidence if hasattr(ent._, 'confidence') else 1.0
                })
                logger.info(f"  - {ent.text} ({ent.start_char}-{ent.end_char})")
        
        return skills

class SkillExtractor:
    """
    Production-ready skill extractor using trained spaCy model
    """
    
    def __init__(self, model_path: str):
        """
        Initialize skill extractor with trained model
        
        Args:
            model_path: Path to the trained spaCy model
        """
        self.model_path = model_path
        self.nlp = None
        self.load_model()
    
    def load_model(self):
        """Load the trained spaCy model"""
        try:
            self.nlp = spacy.load(self.model_path)
            logger.info(f"Loaded model from: {self.model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            logger.info("Falling back to blank English model")
            self.nlp = spacy.blank("en")
    
    def extract_skills(self, text: str) -> List[Dict]:
        """
        Extract skills from text
        
        Args:
            text: Input text to extract skills from
            
        Returns:
            List of extracted skills with metadata
        """
        if not text or not text.strip():
            return []
        
        doc = self.nlp(text)
        
        skills = []
        for ent in doc.ents:
            if ent.label_ == "SKILL":
                skills.append({
                    "text": ent.text,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "label": ent.label_,
                    "confidence": getattr(ent._, 'confidence', 1.0)
                })
        
        return skills
    
    def extract_skills_batch(self, texts: List[str]) -> List[List[Dict]]:
        """
        Extract skills from multiple texts in batch
        
        Args:
            texts: List of input texts
            
        Returns:
            List of skill lists for each input text
        """
        results = []
        
        for doc in self.nlp.pipe(texts):
            skills = []
            for ent in doc.ents:
                if ent.label_ == "SKILL":
                    skills.append({
                        "text": ent.text,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "label": ent.label_,
                        "confidence": getattr(ent._, 'confidence', 1.0)
                    })
            results.append(skills)
        
        return results

if __name__ == "__main__":
    # Example usage
    training_data_path = "../../data/processed/spacy_training_data.json"
    model_output_path = "../../backend/trained_models/skill_extraction_model"
    
    trainer = SkillExtractionTrainer(training_data_path, model_output_path)
    trainer.train_model(n_iter=50, dropout=0.2)
    trainer.save_model()
    
    # Test the trained model
    test_text = "I have experience with Python, machine learning, scikit-learn, and TensorFlow for data science projects."
    trainer.test_model(test_text)
