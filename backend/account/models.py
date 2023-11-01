from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
from django.utils.translation import gettext_lazy as _

#  Custom User Manager
class UserManager(BaseUserManager):
  def create_user(self, email, name, tc, password=None, password2=None):
      """
      Creates and saves a User with the given email, name, tc and password.
      """
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email=self.normalize_email(email),
          name=name,
          tc=tc,
      )

      user.set_password(password)
      user.save(using=self._db)
      return user

  def create_superuser(self, email, name, tc, password=None):
      """
      Creates and saves a superuser with the given email, name, tc and password.
      """
      user = self.create_user(
          email,
          password=password,
          name=name,
          tc=tc,
      )
      user.is_admin = True
      user.save(using=self._db)
      return user

#  Custom User Model
class User(AbstractBaseUser):
  email = models.EmailField(
      verbose_name='Email',
      max_length=255,
      unique=True,
  )
  name = models.CharField(max_length=200)
  tc = models.BooleanField()
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['name', 'tc']

  def __str__(self):
      return self.email

  def has_perm(self, perm, obj=None):
      "Does the user have a specific permission?"
      # Simplest possible answer: Yes, always
      return self.is_admin

  def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

  @property
  def is_staff(self):
      "Is the user a member of staff?"
      # Simplest possible answer: All admins are staff
      return self.is_admin

# Model to save ml runs
class UserSearch(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add=True)
    score = models.IntegerField()

    class urlStatus(models.TextChoices):
        benign = 'BN', _('Benign')
        phishing = 'PS', _('Phishing')
        
    status = models.CharField(choices = urlStatus.choices,max_length = 2)

    def __str__(self):
        return self.user_id
    
    @classmethod
    def create_user_search(cls, user_id, url, score):
        status = 'BN' if score == 0 else 'PS'
        return cls.objects.create(
            user_id=user_id,
            url=url,
            score=score,
            status=status
        )

    @classmethod
    def get_user_searches(cls,user_id,count,skip):
        return cls.objects.filter(user_id=user_id).order_by('-created_at')[skip:skip + count]

    def is_url_safe(self):
        return True if self.status == 'BN' else false

