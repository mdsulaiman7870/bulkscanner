from django import template

register = template.Library()

@register.simple_tag
def dictKeyLookup(the_dict, key):

   
   if the_dict is not None:
    return the_dict.get(key, '')

   else:
    pass

@register.simple_tag
def remove_hyphen_from_dict(the_dict, key):
    
   if the_dict is not None:
    return the_dict.get(key, '-')

   else:
    pass