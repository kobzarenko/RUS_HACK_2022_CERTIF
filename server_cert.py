import datetime
from OpenSSL import crypto
import OpenSSL
import ssl
import socket
import pymysql
import ipaddress
from pymysql.cursors import DictCursor


class CertInfo:
	
	def __init__(self, name, port):
		pem_server_certificate = ssl.get_server_certificate((name, port))
		self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, str.encode(pem_server_certificate))

	def decode_x509name_obj(self, o):
		parts = []
		for c in o.get_components():
			parts.append(c[0].decode('utf-8')  +  '='  +  c[1].decode('utf-8'))
		return ', '.join(parts)

	def cert_date_to_gmt_date(self, d):
		return  datetime.datetime.strptime(d.decode('ascii'), '%Y%m%d%H%M%SZ')

	def cert_date_to_gmt_date_string(self, d):
		return self.cert_date_to_gmt_date(d).strftime("%Y-%m-%d %H:%M:%S GMT")

	def get_item(self, item, extension=None, return_as=None, algo=None):
		try:
			if item == 'subject':
				return self.decode_x509name_obj(self.cert.get_subject())

			elif item == 'subject_o':
				return self.cert.get_subject().O.strip()

			elif item == 'subject_cn':
				return self.cert.get_subject().CN.strip()

			elif item == 'extensions':
				ext_count = self.cert.get_extension_count()
				if extension is  None:
					ext_infos = []
					for i in range (0, ext_count):
						ext = self.cert.get_extension(i)
						ext_infos.append(ext.get_short_name().decode('utf-8'))
					return ext_infos

				for i in range (0, ext_count):
					ext = self.cert.get_extension(i)
					if extension in str(ext.get_short_name()):
						return ext.__str__().strip()
				return  None

			elif item == 'version':
				return self.cert.get_version()

			elif item == 'pubkey_type':
				pk_type = self.cert.get_pubkey().type()
				if pk_type == crypto.TYPE_RSA:
					return 'RSA'
				elif pk_type == crypto.TYPE_DSA:
					return 'DSA'
				return 'Unknown'

			elif item == 'pubkey_pem':
				return crypto.dump_publickey(crypto.FILETYPE_PEM, self.cert.get_pubkey()).decode('utf-8')

			elif item == 'key_len':
				return self.cert.get_pubkey().bits()

			elif item == 'serial_number':
				return self.cert.get_serial_number()

			elif item == 'not_before':
				not_before = self.cert.get_notBefore()
				if return_as == 'string':
					return self.cert_date_to_gmt_date_string(not_before)
				return self.cert_date_to_gmt_date(not_before)

			elif item == 'not_after':
				not_after = self.cert.get_notAfter()
				if return_as == 'string':
					return self.cert_date_to_gmt_date_string(not_after)
				return self.cert_date_to_gmt_date(not_after)

			elif item == 'has_expired':
				return self.cert.has_expired()

			elif item == 'issuer':
				return self.decode_x509name_obj(self.cert.get_issuer())

			elif item == 'issuer_o':
				return self.cert.get_issuer().O.strip()

			elif item == 'issuer_cn':
				return self.cert.get_issuer().CN.strip()

			elif item == 'signature_algorithm':
				return self.cert.get_signature_algorithm().decode('utf-8')

			elif item == 'digest':
				# ['md5', 'sha1', 'sha256', 'sha512']
				return self.cert.digest(algo)

			elif item == 'pem':
				return crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert).decode('utf-8')

			else:
				return  None

		except Exception as e:
			logger.error('item = {}, exception, e = {}'.format(item, e))
			return  None

	@property
	def subject(self):
		return self.get_item('subject')

	@property
	def subject_o(self):
		return self.get_item('subject_o')

	@property
	def subject_cn(self):
		return self.get_item('subject_cn')

	@property
	def subject_name_hash(self):
		return self.get_item('subject_name_hash')

	@property
	def extension_count(self):
		return self.get_item('extension_count')

	@property
	def extensions(self):
		return self.get_item('extensions')

	@property
	def extension_basic_constraints(self):
		return self.get_item('extensions', extension='basicConstraints')

	@property
	def extension_subject_key_identifier(self):
		return self.get_item('extensions', extension='subjectKeyIdentifier')

	@property
	def extension_authority_key_identifier(self):
		return self.get_item('extensions', extension='authorityKeyIdentifier')

	@property
	def extension_subject_alt_name(self):
		return self.get_item('extensions', extension='subjectAltName')

	@property
	def version(self):
		return self.get_item('version')

	@property
	def pubkey_type(self):
		return self.get_item('pubkey_type')

	@property
	def pubkey_pem(self):
		return self.get_item('pubkey_pem')

	@property
	def serial_number(self):
		return self.get_item('serial_number')

	@property
	def not_before(self):
		return self.get_item('not_before')

	@property
	def not_before_s(self):
		return self.get_item('not_before', return_as='string')

	@property
	def not_after(self):
		return self.get_item('not_after')

	@property
	def not_after_s(self):
		return self.get_item('not_after', return_as='string')

	@property
	def has_expired(self):
		return self.get_item('has_expired')

	@property
	def issuer(self):
		return self.get_item('issuer')

	@property
	def issuer_o(self):
		return self.get_item('issuer_o')

	@property
	def issuer_cn(self):
		return self.get_item('issuer_cn')

	@property
	def signature_algorithm(self):
		return self.get_item('signature_algorithm')

	@property
	def digest_sha256(self):
		return self.get_item('digest', algo='sha256')

	@property
	def pem(self):
		return self.get_item('pem')

	@property
	def key_len(self):
		return self.get_item('key_len')


def ip2dn(addr):
	return socket.gethostbyaddr(addr)[0]

def format_cert_items(m):
	return '{}: {}'.format(m[0], m[1])

def db_module(cur, action, data=None):
	if action == 'write':
		sql = "INSERT INTO certs (addr, port, time, trust) VALUES (%s, %s, %s, %s)"
		cur.execute(sql, (data['addr'], str(data['port']), str(data['time']), str(data['trust'])))
	elif action == 'get':
		cur.execute("SELECT * FROM bad_issuers")
		bad_issuers = cur.fetchall()

		return bad_issuers
	elif action == 'add':
		sql = "INSERT INTO bad_issuers (name) VALUES (%s)"
		cur.execute(sql, (data))

def check_cert(ci, cur):
	bad_issuers = db_module(cur, action='get')
	
	if (ci['Not after'] - ci['Not before']).days > 800:
		db_module(cur, 'add', data=ci['Issuer-CN'])
		return False
	elif ci['Has expired']:
		db_module(cur, 'add', data=ci['Issuer-CN'])
		return False
	elif ci['Extension-subjectKeyIdentifier'] == ci['Extension-authorityKeyIdentifier']:
		db_module(cur, 'add', data=ci['Issuer-CN'])
		return False
	elif ci['Issuer-CN'] in bad_issuers:
		return False
	elif (ci['Not after'] - datetime.datetime.now()).days < 60:
		db_module(cur, 'add', data=ci['Issuer-CN'])
		return False
	elif ci['Key length'] < 2048:
		db_module(cur, 'add', data=ci['Issuer-CN'])
		return False
	elif ('rsa' not in ci['Signature algortihm'].lower()) or ('sha256' not in ci['Signature algortihm'].lower()):
		db_module(cur, 'add', data=ci['Issuer-CN'])
		return False

	return True

def cert2dict(ci):
	cert_items = {
		'Subject': ci.subject,
		'Subject-CN': ci.subject_cn,
		'Subject name hash': ci.subject_name_hash,
		'Issuer': ci.issuer,
		'Issuer-CN': ci.issuer_cn,
		'Extensions': ci.extensions,
		'Extension-basicConstraints': ci.extension_basic_constraints,
		'Extension-subjectKeyIdentifier': ci.extension_subject_key_identifier,
		'Extension-authorityKeyIdentifier': ci.extension_authority_key_identifier,
		'Extension-subjectAltName SAN': ci.extension_subject_alt_name,
		'Version': ci.version,
		'Serial_number': ci.serial_number,
		'Public key-type': ci.pubkey_type,
		'Public key-pem': ci.pubkey_pem,
		'Not before': ci.not_before,
		'Not after': ci.not_after,
		'Has expired': ci.has_expired,
		'Signature algortihm': ci.signature_algorithm,
		'Digest-sha256': ci.digest_sha256,
		'PEM': ci.pem,
		'Key length': ci.key_len
		}
	return cert_items


def proc_certs(cur, name=None, data=None):
	if name != None:
		with open(name, 'r', encoding='utf-8') as f:
			addr_data = f.read().split('\n')
	if data != None:
		addr_data = data
	print(addr_data)

	# Ввод по IP-аресам недоработан, так как получение доменного имени по адресу возможно с PTR-записью
	# На доменах работает отлично
	# Преобразование адреса в домен производится функцией ip2dn; в 317 строке происходит обращение по домену для сравнения

	for i in range(len(addr_data)):
		addr, port = addr_data[i].split(';')
		if '/' in addr:
			for el in list(ipaddress.ip_network(addr).hosts()):
				try:
					ci = cert2dict(CertInfo(ip2dn(str(el)), port))
					cert_data = {'addr':str(el), 'port':port, 'time':datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S"), 'trust':check_cert(ci, cur)}
					db_module(cur, 'write', data=cert_data)
				except:
					print('Lose')
					continue
		else:
			try:
				ci = cert2dict(CertInfo(addr, port))
				cert_data = {'addr':addr, 'port':port, 'time':datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S"), 'trust':check_cert(ci, cur)}
				db_module(cur, 'write', data=cert_data)
			except:
				print('Lose')
				continue


connection = pymysql.connect(
	host='',
	user='',
	password='',
	db='',
	charset='utf8mb4',
	cursorclass=DictCursor,
	autocommit=True
)
cur = connection.cursor()

proc_certs(cur, name='data.csv')















