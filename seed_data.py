from app import app, db, User, Event, Sponsorship, Rating, Notification, BlogPost, Feedback
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def seed_database():
    """Seed the database with initial data."""
    with app.app_context():
        try:
            # Clear existing data
            logger.info("Clearing existing data...")
            Feedback.query.delete()
            BlogPost.query.delete()
            Notification.query.delete()
            Rating.query.delete()
            Sponsorship.query.delete()
            Event.query.delete()
            User.query.delete()
            db.session.commit()
            logger.info("Existing data cleared.")

            # Create users
            logger.info("Creating users...")
            # Create individual seekers
            individual_seekers = [
                User(
                    username='john_doe',
                    email='john@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='seeker',
                    seeker_type='individual',
                    first_name='John',
                    last_name='Doe',
                    location='San Francisco, CA',
                    bio='Passionate about technology and education',
                    skills=['Python', 'JavaScript', 'Web Development'],
                    achievements='Winner of National Coding Competition 2023\nBest Student Project Award 2022',
                    resume_url='https://example.com/john-resume',
                    portfolio_url='https://johndoe.dev',
                    rating=4.8
                ),
                User(
                    username='sarah_smith',
                    email='sarah@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='seeker',
                    seeker_type='individual',
                    first_name='Sarah',
                    last_name='Smith',
                    location='New York, NY',
                    bio='AI researcher and ML enthusiast',
                    skills=['Machine Learning', 'Deep Learning', 'Research'],
                    achievements='Published in top AI conferences\nPhD Candidate at NYU',
                    resume_url='https://example.com/sarah-resume',
                    portfolio_url='https://sarahsmith.ai',
                    rating=4.9
                )
            ]

            # Create organization seekers
            org_seekers = [
                User(
                    username='mit_lab',
                    email='mitlab@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='seeker',
                    seeker_type='organization',
                    organization_name='MIT Innovation Lab',
                    organization_type='research',
                    sector='Technology Research',
                    mission_statement='Advancing technology through innovative research',
                    founding_date=datetime(2010, 1, 1),
                    verification_status=True,
                    location='Cambridge, MA',
                    rating=4.9
                ),
                User(
                    username='edu_foundation',
                    email='edufound@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='seeker',
                    seeker_type='organization',
                    organization_name='Global Education Foundation',
                    organization_type='non_profit',
                    sector='Education',
                    mission_statement='Making quality education accessible to all',
                    founding_date=datetime(2015, 6, 15),
                    verification_status=True,
                    location='Chicago, IL',
                    rating=4.7
                )
            ]

            # Create sponsors
            sponsors = [
                User(
                    username='tech_corp',
                    email='techcorp@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='sponsor',
                    company_name='TechCorp Inc.',
                    industry='Technology',
                    sponsorship_budget=100000.0,
                    sponsorship_goals='Support innovative tech projects and research',
                    location='Silicon Valley, CA',
                    bio='Leading technology company supporting education',
                    rating=4.8
                ),
                User(
                    username='global_edu',
                    email='globaledu@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='sponsor',
                    company_name='Global Education Partners',
                    industry='Education',
                    sponsorship_budget=50000.0,
                    sponsorship_goals='Empowering educational initiatives worldwide',
                    location='Boston, MA',
                    bio='International education support organization',
                    rating=4.7
                ),
                User(
                    username='innovation_fund',
                    email='innofund@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='sponsor',
                    company_name='Innovation Fund',
                    industry='Venture Capital',
                    sponsorship_budget=200000.0,
                    sponsorship_goals='Funding breakthrough research and innovation',
                    location='New York, NY',
                    bio='Leading venture capital firm focused on education and research',
                    rating=4.9
                ),
                User(
                    username='future_tech',
                    email='futuretech@example.com',
                    password_hash=generate_password_hash('password123'),
                    role='sponsor',
                    company_name='Future Technologies Ltd',
                    industry='Technology',
                    sponsorship_budget=150000.0,
                    sponsorship_goals='Supporting next-generation technology development',
                    location='Seattle, WA',
                    bio='Pioneering technology company investing in the future',
                    rating=4.6
                )
            ]

            # Add all users to database
            for user in individual_seekers + org_seekers + sponsors:
                db.session.add(user)
            db.session.commit()
            logger.info("Users created successfully")

            # Create events
            logger.info("Creating events...")
            events = [
                Event(
                    title='AI Research Symposium 2024',
                    description='International symposium on artificial intelligence research and applications',
                    short_description='Bringing together AI researchers and practitioners',
                    date=datetime.now() + timedelta(days=30),
                    location='Cambridge, MA',
                    funding_goal=25000.0,
                    current_funding=15000.0,
                    organizer_id=org_seekers[0].id,
                    category='Technology',
                    is_featured=True
                ),
                Event(
                    title='Global Education Summit',
                    description='Annual summit focusing on global education challenges and solutions',
                    short_description='Addressing global education challenges',
                    date=datetime.now() + timedelta(days=60),
                    location='Chicago, IL',
                    funding_goal=35000.0,
                    current_funding=20000.0,
                    organizer_id=org_seekers[1].id,
                    category='Education',
                    is_featured=True
                ),
                Event(
                    title='Coding Bootcamp Scholarship Program',
                    description='Intensive coding bootcamp for underprivileged students',
                    short_description='Empowering through code education',
                    date=datetime.now() + timedelta(days=45),
                    location='San Francisco, CA',
                    funding_goal=15000.0,
                    current_funding=7500.0,
                    organizer_id=individual_seekers[0].id,
                    category='Education'
                )
            ]
            
            for event in events:
                db.session.add(event)
            db.session.commit()
            logger.info("Events created successfully")

            # Create sponsorships
            logger.info("Creating sponsorships...")
            sponsorships = [
                Sponsorship(
                    event_id=events[0].id,
                    sponsor_id=sponsors[0].id,
                    amount=10000.0,
                    status='approved',
                    message='Excited to support AI research!'
                ),
                Sponsorship(
                    event_id=events[1].id,
                    sponsor_id=sponsors[1].id,
                    amount=15000.0,
                    status='approved',
                    message='Supporting global education initiatives'
                ),
                Sponsorship(
                    event_id=events[2].id,
                    sponsor_id=sponsors[2].id,
                    amount=5000.0,
                    status='pending',
                    message='Interested in supporting coding education'
                )
            ]
            
            for sponsorship in sponsorships:
                db.session.add(sponsorship)
            db.session.commit()
            logger.info("Sponsorships created successfully")

            logger.info("Database seeding completed successfully")

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error seeding database: {e}")
            raise

if __name__ == '__main__':
    seed_database() 