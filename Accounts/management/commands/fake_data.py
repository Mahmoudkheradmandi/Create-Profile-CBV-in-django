
from django.core.management.base import BaseCommand
from faker import Faker
from Accounts.models import User, Profile


class Command(BaseCommand):
    help = " insert fake data "

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.fake = Faker()

    def handle(self, *args, **options):
        user = User.objects.create_user(
            email=self.fake.email(), password="A?!@12345"
        )
        profile = Profile.objects.get(user=user)
        profile.first_name = self.fake.first_name_male()
        profile.last_name = self.fake.last_name()
        profile.description = self.fake.paragraph(nb_sentences=4)
        profile.save()
        print(user, profile)
