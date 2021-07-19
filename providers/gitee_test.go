package providers

import (
	"testing"

	"github.com/onsi/gomega"
)

func TestNewGiteeProvider(t *testing.T) {
	g := gomega.NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewGiteeProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(gomega.Equal("Gitee"))
	g.Expect(providerData.LoginURL.String()).To(gomega.Equal("https://gitee.com/login/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(gomega.Equal("https://gitee.com/login/oauth/access_token"))
	g.Expect(providerData.ProfileURL.String()).To(gomega.Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(gomega.Equal("https://github.com/api/v5"))
	g.Expect(providerData.Scope).To(gomega.Equal("user_info emails"))
}
