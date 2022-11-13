from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy

desired_caps = dict(
	platformName='iOS',
	platformVersion='14.4',
	deviceName='iPhone 6s',
	automationName='xcuitest',
	udid='c5b7903056d30974db4cc14eb07617196735dc75',
)

driver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desired_caps)
while True:
	with open('page.xml', 'w') as f:
		f.write(driver.page_source)

	input("enter a key to save the current view...")