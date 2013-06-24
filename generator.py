import os

class Generator:
    def generate_html(self, filename, domains):
        nav = '<div id="nav"><ul style="display:inline">'
        li = '<ul>'
        last = '-'
        for d in domains:
            if not last[0] == d[0]:
                last = d
                nav = '%s<li><a href="#%s">%s</a></li>'%(nav,d[0].upper(),d[0].upper())
                li = '%s</ul>\n<h3><a name="%s">%s</a></h3>\n<ul>'%(li,d[0].upper(),d[0].upper())
            li = '%s<li>%s</li>\n'%(li,d)

        nav = '%s</ul></div>\n'%nav
        li = '%s</ul>\n'%li

        if not os.path.exists('html_out'):
            os.makedirs('html_out')
        
        out = open('html_out/'+filename, 'w')
        out.write('<html><head><title>Free short .de domains</title></head>\n')
        out.write('<style media="screen" type="text/css">#nav ul, #nav li { display: inline; padding: 5px; }</style>')
        out.write('<body>\n')
        out.write(nav)
        out.write(li)
        out.write('</body></html>\n')
