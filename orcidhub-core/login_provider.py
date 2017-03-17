from application import login_manager
from functools import wraps
from flask_login import current_user
from models import User

def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            for r in roles:
                if current_user.has_role(r):
                    return fn(*args, **kwargs)
            else:
                return login_manager.unauthorized()

        return decorated_view
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    """Given *user_id*, return the associated User object.

    :param unicode user_id: user_id (email) user to retrieve
    """
    return User.get(id=user_id)
