import { InstanceDto } from '@api/dto/instance.dto';
import { cache, prismaRepository, waMonitor } from '@api/server.module';
import { Integration } from '@api/types/wa.types';
import { Auth, configService, Database } from '@config/env.config';
import { Logger } from '@config/logger.config';
import { ForbiddenException, UnauthorizedException } from '@exceptions';
import { NextFunction, Request, Response } from 'express';

const logger = new Logger('GUARD');

async function apikey(req: Request, _: Response, next: NextFunction) {
  const env = configService.get<Auth>('AUTHENTICATION').API_KEY;
  const key = req.get('apikey');
  const db = configService.get<Database>('DATABASE');

  if (!key) {
    throw new UnauthorizedException();
  }

  if (env.KEY === key) {
    return next();
  }

  if ((req.originalUrl.includes('/instance/create') || req.originalUrl.includes('/instance/fetchInstances')) && !key) {
    throw new ForbiddenException('Missing global api key', 'The global api key must be set');
  }
  const param = req.params as unknown as InstanceDto;

  try {
    if (param?.instanceName) {
      const instance = await prismaRepository.instance.findUnique({
        where: { name: param.instanceName },
      });
      const keyToCompare = key.length > 255 ? key.substring(0, 255) : key;
      if (instance.token === keyToCompare) {
        // Se o token fornecido é maior que 255 e a instância é WhatsApp Business, salva no cache
        if (key.length > 255 && instance.integration === Integration.WHATSAPP_BUSINESS) {
          const cacheKey = `instance:${param.instanceName}:fullToken`;
          await cache.set(cacheKey, key, 0);
          logger.log(`Stored full token in cache for ${param.instanceName} from request`);

          // Atualiza a instância em memória se existir
          if (waMonitor.waInstances[param.instanceName]) {
            const waInstance = waMonitor.waInstances[param.instanceName];
            if (waInstance && typeof (waInstance as any).setInstance === 'function') {
              try {
                await (waInstance as any).setInstance({
                  instanceName: param.instanceName,
                  instanceId: instance.id,
                  integration: instance.integration,
                  token: key,
                  number: instance.number,
                  businessId: instance.businessId,
                });
                logger.log(`Updated full token in memory for ${param.instanceName}`);
              } catch (error) {
                logger.error(`Error updating token in memory: ${error}`);
              }
            }
          }
        }
        return next();
      }
    } else {
      if (req.originalUrl.includes('/instance/fetchInstances') && db.SAVE_DATA.INSTANCE) {
        const keyToCompare = key.length > 255 ? key.substring(0, 255) : key;
        const instanceByKey = await prismaRepository.instance.findFirst({
          where: { token: keyToCompare },
        });
        if (instanceByKey) {
          // Se o token fornecido é maior que 255 e a instância é WhatsApp Business, salva no cache
          if (key.length > 255 && instanceByKey.integration === Integration.WHATSAPP_BUSINESS) {
            const cacheKey = `instance:${instanceByKey.name}:fullToken`;
            await cache.set(cacheKey, key, 0);
            logger.log(`Stored full token in cache for ${instanceByKey.name} from request`);

            // Atualiza a instância em memória se existir
            if (waMonitor.waInstances[instanceByKey.name]) {
              const waInstance = waMonitor.waInstances[instanceByKey.name];
              if (waInstance && typeof (waInstance as any).setInstance === 'function') {
                try {
                  await (waInstance as any).setInstance({
                    instanceName: instanceByKey.name,
                    instanceId: instanceByKey.id,
                    integration: instanceByKey.integration,
                    token: key,
                    number: instanceByKey.number,
                    businessId: instanceByKey.businessId,
                  });
                  logger.log(`Updated full token in memory for ${instanceByKey.name}`);
                } catch (error) {
                  logger.error(`Error updating token in memory: ${error}`);
                }
              }
            }
          }
          return next();
        }
      }
    }
  } catch (error) {
    logger.error(error);
  }

  throw new UnauthorizedException();
}

export const authGuard = { apikey };
