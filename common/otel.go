package common

import (
	"regexp"
	"strings"
)

var (
	deploymentPodRegex  = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-[0-9a-f]{1,10}-[bcdfghjklmnpqrstvwxz2456789]{5}/.+`)
	daemonsetPodRegex   = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-[bcdfghjklmnpqrstvwxz2456789]{5}/.+`)
	statefulsetPodRegex = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-\d+/.+`)
	cronjobPodRegex     = regexp.MustCompile(`(/k8s-cronjob/[a-z0-9-]+/[a-z0-9-]+)/.+`)
)

func ContainerIdToOtelServiceName(containerId string) string {
	// 对 k8s 容器做特殊处理，将 pod 名称作为 service name·
	if strings.HasPrefix(containerId, "/k8s/") {
		for _, r := range []*regexp.Regexp{deploymentPodRegex, daemonsetPodRegex, statefulsetPodRegex, cronjobPodRegex} {
			if g := r.FindStringSubmatch(containerId); len(g) == 2 {
				return g[1]
			}
		}
	}
	// 对 docker 容器不做处理，将 container id 作为 service name。
	// 对于其他类型的容器，也不做处理，将 container id 作为 service name。
	return containerId
}
